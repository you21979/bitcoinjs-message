const bs58check = require('bs58check') as any;
const bech32 = require('bech32') as any;
const bufferEquals = require('buffer-equals') as any;
const createHash = require('create-hash') as any;
const secp256k1 = require('secp256k1') as any;
import * as varuint from 'varuint-bitcoin'

const SEGWIT_TYPES = {
  P2WPKH: 'p2wpkh',
  P2SH_P2WPKH: 'p2sh(p2wpkh)'
}

interface DecodeSignatureInterface{
  compressed: boolean;
  segwitType: string | null;
  recovery: number;
  signature: Buffer;
}

interface SigOptionsInterface {
  segwitType: string;
  extraEntropy: Buffer;
}

function sha256 (b: Buffer): Buffer {
  return createHash('sha256')
    .update(b)
    .digest()
}
function hash256 (buffer: Buffer): Buffer {
  return sha256(sha256(buffer))
}
function hash160 (buffer: Buffer): Buffer {
  return createHash('ripemd160')
    .update(sha256(buffer))
    .digest()
}

function encodeSignature (signature: Buffer, recovery: number, compressed: boolean, segwitType?: string): Buffer {
  if (segwitType !== undefined) {
    recovery += 8
    if (segwitType === SEGWIT_TYPES.P2WPKH) recovery += 4
  } else {
    if (compressed) recovery += 4
  }
  return Buffer.concat([Buffer.alloc(1, recovery + 27), signature])
}

function decodeSignature (buffer: Buffer): DecodeSignatureInterface {
  if (buffer.length !== 65) throw new Error('Invalid signature length')

  const flagByte = buffer.readUInt8(0) - 27
  if (flagByte > 15 || flagByte < 0) {
    throw new Error('Invalid signature parameter')
  }

  return {
    compressed: !!(flagByte & 12),
    segwitType: !(flagByte & 8)
      ? null
      : !(flagByte & 4)
        ? SEGWIT_TYPES.P2SH_P2WPKH
        : SEGWIT_TYPES.P2WPKH,
    recovery: flagByte & 3,
    signature: buffer.slice(1)
  }
}

function magicHash (message: string, messagePrefix?: string| Buffer): Buffer {
  messagePrefix = messagePrefix || '\u0018Bitcoin Signed Message:\n'
  if (!Buffer.isBuffer(messagePrefix)) {
    messagePrefix = Buffer.from(messagePrefix, 'utf8')
  }

  const messageVISize = varuint.encodingLength(message.length)
  const buffer = Buffer.allocUnsafe(
    messagePrefix.length + messageVISize + message.length
  )
  messagePrefix.copy(buffer, 0)
  varuint.encode(message.length, buffer, messagePrefix.length)
  buffer.write(message, messagePrefix.length + messageVISize)
  return hash256(buffer)
}

function sign (
  message: string,
  privateKey: string,
  compressed: boolean,
  messagePrefix?: any,
  sigOptions?: SigOptionsInterface,
): Buffer {
  if (typeof messagePrefix === 'object' && sigOptions === undefined) {
    sigOptions = messagePrefix
    messagePrefix = undefined
  }
  let { segwitType, extraEntropy } = sigOptions || {}
  if (
    segwitType &&
    (typeof segwitType === 'string' || (segwitType as any) instanceof String)
  ) {
    segwitType = segwitType.toLowerCase()
  }
  if (
    segwitType &&
    segwitType !== SEGWIT_TYPES.P2SH_P2WPKH &&
    segwitType !== SEGWIT_TYPES.P2WPKH
  ) {
    throw new Error(
      'Unrecognized segwitType: use "' +
        SEGWIT_TYPES.P2SH_P2WPKH +
        '" or "' +
        SEGWIT_TYPES.P2WPKH +
        '"'
    )
  }
  const hash = magicHash(message, messagePrefix)
  const sigObj = secp256k1.sign(hash, privateKey, { data: extraEntropy })
  return encodeSignature(
    sigObj.signature,
    sigObj.recovery,
    compressed,
    segwitType
  )
}

function verify (message: string, address: string, signature: string | Buffer, messagePrefix: string): boolean {
  if (!Buffer.isBuffer(signature)) signature = Buffer.from(signature, 'base64')

  const parsed = decodeSignature(signature)
  const hash = magicHash(message, messagePrefix)
  const publicKey = secp256k1.recover(
    hash,
    parsed.signature,
    parsed.recovery,
    parsed.compressed
  )
  const publicKeyHash = hash160(publicKey)
  let actual, expected

  if (parsed.segwitType) {
    if (parsed.segwitType === SEGWIT_TYPES.P2SH_P2WPKH) {
      const redeemScript = Buffer.concat([
        Buffer.from('0014', 'hex'),
        publicKeyHash
      ])
      const redeemScriptHash = hash160(redeemScript)
      actual = redeemScriptHash
      expected = bs58check.decode(address).slice(1)
    } else if (parsed.segwitType === SEGWIT_TYPES.P2WPKH) {
      const result = bech32.decode(address)
      const data = bech32.fromWords(result.words.slice(1))
      actual = publicKeyHash
      expected = Buffer.from(data)
    }
  } else {
    actual = publicKeyHash
    expected = bs58check.decode(address).slice(1)
  }

  return bufferEquals(actual, expected)
}

export {
  magicHash,
  sign,
  verify,
  SigOptionsInterface
}
