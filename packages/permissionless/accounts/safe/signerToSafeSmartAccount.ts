import {
    type Address,
    type Chain,
    type Client,
    type Hash,
    type Hex,
    type SignableMessage,
    type Transport,
    type TypedData,
    type TypedDataDefinition,
    encodeFunctionData,
    encodePacked,
    hashMessage,
    hashTypedData
} from "viem"
import { getChainId } from "viem/actions"
import type {
    EntryPointVersion,
    GetEntryPointVersion,
    Prettify
} from "../../types"
import type { EntryPoint, UserOperation } from "../../types"
import { toSmartAccount } from "../toSmartAccount"
import {
    SignTransactionNotSupportedBySmartAccount,
    type SmartAccount,
    type SmartAccountSigner
} from "../types"

import Safe, {
    EthersAdapter,
    getProxyFactoryContract
} from "@safe-global/protocol-kit"
import {
    Safe4337Pack,
    UserOperation as SafeUserOperation
} from "@safe-global/relay-kit"
import { ethers } from "ethers"
import SafeOperation from "@safe-global/relay-kit/dist/src/packs/safe-4337/SafeOperation"

import {
    type MetaTransactionData,
    type EIP712TypedData,
    OperationType
} from "@safe-global/safe-core-sdk-types"

export type SafeVersion = "1.4.1"

// const EIP712_SAFE_OPERATION_TYPE_V06 = { SafeOp: "v0.2" }

// const EIP712_SAFE_OPERATION_TYPE_V07 = { SafeOp: "v0.3" }

const generateSafeMessageMessage = <
    const TTypedData extends TypedData | { [key: string]: unknown },
    TPrimaryType extends keyof TTypedData | "EIP712Domain" = keyof TTypedData
>(
    message: SignableMessage | TypedDataDefinition<TTypedData, TPrimaryType>
): Hex => {
    const signableMessage = message as SignableMessage

    if (typeof signableMessage === "string" || signableMessage.raw) {
        return hashMessage(signableMessage)
    }

    return hashTypedData(
        message as TypedDataDefinition<TTypedData, TPrimaryType>
    )
}

const SAFE_VERSION_TO_ADDRESSES_MAP: {
    [key in SafeVersion]: {
        [key in EntryPointVersion]: string
    }
} = {
    "1.4.1": {
        "v0.6": "0.2",
        "v0.7": "0.3"
    }
}

const encodeInternalTransaction = (tx: {
    to: Address
    data: Address
    value: bigint
    operation: 0 | 1
}): string => {
    const encoded = encodePacked(
        ["uint8", "address", "uint256", "uint256", "bytes"],
        [
            tx.operation,
            tx.to,
            tx.value,
            BigInt(tx.data.slice(2).length / 2),
            tx.data
        ]
    )
    return encoded.slice(2)
}

const encodeMultiSend = (
    txs: {
        to: Address
        data: Address
        value: bigint
        operation: 0 | 1
    }[]
): `0x${string}` => {
    const data: `0x${string}` = `0x${txs
        .map((tx) => encodeInternalTransaction(tx))
        .join("")}`

    return encodeFunctionData({
        abi: [
            {
                inputs: [
                    {
                        internalType: "bytes",
                        name: "transactions",
                        type: "bytes"
                    }
                ],
                name: "multiSend",
                outputs: [],
                stateMutability: "payable",
                type: "function"
            }
        ],
        functionName: "multiSend",
        args: [data]
    })
}

export type SafeSmartAccount<
    entryPoint extends EntryPoint,
    transport extends Transport = Transport,
    chain extends Chain | undefined = Chain | undefined
> = SmartAccount<entryPoint, "SafeSmartAccount", transport, chain>

export type SignerToSafeSmartAccountParameters<
    entryPoint extends EntryPoint,
    TSource extends string = string,
    TAddress extends Address = Address
> = Prettify<{
    signer: SmartAccountSigner<TSource, TAddress>
    safeVersion: SafeVersion
    entryPoint: entryPoint
    address?: Address
    safeModuleSetupAddress?: Address
    safe4337ModuleAddress?: Address
    safeProxyFactoryAddress?: Address
    safeSingletonAddress?: Address
    multiSendAddress?: Address
    multiSendCallOnlyAddress?: Address
    saltNonce?: bigint
    validUntil?: number
    validAfter?: number
    setupTransactions?: {
        to: Address
        data: Address
        value: bigint
    }[]
    safeModules?: Address[]
}>

/**
 * @description Creates an Simple Account from a private key.
 *
 * @returns A Private Key Simple Account.
 */
export async function signerToSafeSmartAccount<
    entryPoint extends EntryPoint,
    TTransport extends Transport = Transport,
    TChain extends Chain | undefined = Chain | undefined,
    TSource extends string = string,
    TAddress extends Address = Address
>(
    client: Client<TTransport, TChain>,
    {
        signer,
        address,
        safeVersion,
        entryPoint: entryPointAddress,
        safeModuleSetupAddress: _safeModuleSetupAddress,
        safe4337ModuleAddress: _safe4337ModuleAddress,
        safeProxyFactoryAddress: _safeProxyFactoryAddress,
        safeSingletonAddress: _safeSingletonAddress,
        multiSendAddress: _multiSendAddress,
        multiSendCallOnlyAddress: _multiSendCallOnlyAddress,
        // saltNonce = BigInt(0),
        validUntil = 0,
        validAfter = 0
        // safeModules = [],
        // setupTransactions = []
    }: SignerToSafeSmartAccountParameters<entryPoint, TSource, TAddress>
): Promise<SafeSmartAccount<entryPoint, TTransport, TChain>> {
    const chainId = client.chain?.id ?? (await getChainId(client))

    const ethersAdapter = new EthersAdapter({
        ethers,
        signerOrProvider: ethers.getDefaultProvider(client.transport.url)
    })

    // We assume a 1 out of 1
    const safe4337pack = await Safe4337Pack.init({
        ethersAdapter,
        bundlerUrl: client.transport.url,
        rpcUrl: client.transport.url,
        options: {
            owners: [signer.address],
            threshold: 1
        }
    })

    const protocolKit: Safe = safe4337pack.protocolKit
    const safeAddress = await protocolKit.getAddress()

    if (!safeAddress) throw new Error("Account address not found")
    const accountAddress = safeAddress as Address

    let safeDeployed = await protocolKit.isSafeDeployed()

    const customContracts =
        protocolKit.getContractManager().contractNetworks?.[chainId.toString()]

    const safeSmartAccount: SafeSmartAccount<entryPoint, TTransport, TChain> =
        toSmartAccount({
            address: accountAddress,
            async signMessage({ message }) {
                const rawMessage = generateSafeMessageMessage(message)
                const safeMessage = await protocolKit.createMessage(rawMessage)
                const signedMessage = await protocolKit.signMessage(safeMessage)
                return signedMessage.encodedSignatures() as Hex
            },
            async signTransaction(_, __) {
                throw new SignTransactionNotSupportedBySmartAccount()
            },
            async signTypedData<
                const TTypedData extends TypedData | Record<string, unknown>,
                TPrimaryType extends
                    | keyof TTypedData
                    | "EIP712Domain" = keyof TTypedData
            >(typedData: TypedDataDefinition<TTypedData, TPrimaryType>) {
                const safeMessage = await protocolKit.createMessage(
                    typedData as EIP712TypedData
                )
                const signature = await protocolKit.signTypedData(safeMessage)
                return signature.data as Hash
            },
            client: client,
            publicKey: accountAddress,
            entryPoint: entryPointAddress,
            source: "SafeSmartAccount",
            async getNonce() {
                const nonce = await protocolKit.getNonce()
                return BigInt(nonce)
            },
            async signUserOperation(
                userOperation: UserOperation<GetEntryPointVersion<entryPoint>>
            ) {
                const safeUserOperation = {
                    sender: userOperation.sender || "0x",
                    nonce: userOperation.nonce.toString(),
                    initCode: userOperation.initCode || "0x",
                    callData: userOperation.callData || "0x",
                    callGasLimit: userOperation.callGasLimit,
                    verificationGasLimit: userOperation.verificationGasLimit,
                    preVerificationGas: userOperation.preVerificationGas,
                    maxFeePerGas: userOperation.maxFeePerGas,
                    maxPriorityFeePerGas: userOperation.maxPriorityFeePerGas,
                    paymasterAndData: userOperation.paymasterAndData || "0x",
                    signature: "0x"
                }

                const safeOperation = new SafeOperation(
                    safeUserOperation as SafeUserOperation,
                    {
                        entryPoint: entryPointAddress,
                        validUntil,
                        validAfter
                    }
                )

                const signedOperation =
                    await safe4337pack.signSafeOperation(safeOperation)
                const operation = signedOperation.toUserOperation()
                return operation.signature as Hex
            },
            async getInitCode() {
                safeDeployed =
                    safeDeployed || (await protocolKit.isSafeDeployed())

                if (safeDeployed) return "0x"

                return (await protocolKit.getInitCode()) as Hex
            },
            async getFactory() {
                safeDeployed =
                    safeDeployed || (await protocolKit.isSafeDeployed())

                if (safeDeployed) return undefined

                const safeProxyFactoryAddress =
                    customContracts?.safeProxyFactoryAddress

                return safeProxyFactoryAddress as Hex
            },
            async getFactoryData() {
                const safeProxyFactoryContract = await getProxyFactoryContract({
                    ethAdapter: ethersAdapter,
                    safeVersion,
                    customContracts
                })

                return (await safeProxyFactoryContract.proxyCreationCode()) as Hex
            },
            async encodeDeployCallData(_) {
                throw new Error(
                    "Safe account doesn't support account deployment"
                )
            },
            async encodeCallData(args) {
                // Verify if this is tied with multisend logic
                const transactionsData = Array.isArray(args) ? args : [args]
                const transactions = transactionsData.map(
                    ({ to, value, data }) => {
                        return {
                            to: to as Hex,
                            value: value.toString(),
                            data: data as Hex,
                            operation: OperationType.Call
                        } as MetaTransactionData
                    }
                )

                const safeOperation = await safe4337pack.createTransaction({
                    transactions
                })
                return safeOperation.toUserOperation().callData as Hex
            },
            async getDummySignature(_userOperation) {
                return "0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            }
        })

    return safeSmartAccount
}
