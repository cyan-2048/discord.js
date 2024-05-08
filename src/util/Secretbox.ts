import { Buffer } from "buffer";
import tweetnacl from "tweetnacl";

interface Methods {
	close(opusPacket: Buffer, nonce: Buffer, secretKey: Uint8Array): Buffer;
	open(buffer: Buffer, nonce: Buffer, secretKey: Uint8Array): Buffer | null;
	random(bytes: number, nonce: Buffer): Buffer;
}

const methods: Methods = {
	open: (buffer: Buffer, nonce: Buffer, secretKey: Uint8Array) => {
		const _buffer = new Uint8Array(buffer);
		const _nonce = new Uint8Array(nonce);

		const result = tweetnacl.secretbox.open(_buffer, _nonce, secretKey);

		return result === null ? null : Buffer.from(result);
	},
	close: (opusPacket: Buffer, nonce: Buffer, secretKey: Uint8Array) => {
		const _opusPacket = new Uint8Array(opusPacket);
		const _nonce = new Uint8Array(nonce);

		return Buffer.from(tweetnacl.secretbox(_opusPacket, _nonce, secretKey));
	},
	random: (bytes: number) => {
		return Buffer.from(tweetnacl.randomBytes(bytes));
	},
} as const;

export { methods };
