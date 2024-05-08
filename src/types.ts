/**
 * https://discord.com/developers/docs/topics/opcodes-and-status-codes#gateway-gateway-opcodes
 */
export const enum GatewayOpcodes {
	/**
	 * An event was dispatched
	 */
	Dispatch = 0,
	/**
	 * A bidirectional opcode to maintain an active gateway connection.
	 * Fired periodically by the client, or fired by the gateway to request an immediate heartbeat from the client.
	 */
	Heartbeat = 1,
	/**
	 * Starts a new session during the initial handshake
	 */
	Identify = 2,
	/**
	 * Update the client's presence
	 */
	PresenceUpdate = 3,
	/**
	 * Used to join/leave or move between voice channels
	 */
	VoiceStateUpdate = 4,
	/**
	 * Resume a previous session that was disconnected
	 */
	Resume = 6,
	/**
	 * You should attempt to reconnect and resume immediately
	 */
	Reconnect = 7,
	/**
	 * Request information about offline guild members in a large guild
	 */
	RequestGuildMembers = 8,
	/**
	 * The session has been invalidated. You should reconnect and identify/resume accordingly
	 */
	InvalidSession = 9,
	/**
	 * Sent immediately after connecting, contains the `heartbeat_interval` to use
	 */
	Hello = 10,
	/**
	 * Sent in response to receiving a heartbeat to acknowledge that it has been received
	 */
	HeartbeatAck = 11,
}

/**
 * https://discord.com/developers/docs/topics/opcodes-and-status-codes#voice-voice-opcodes
 */
export const enum VoiceOpcodes {
	/**
	 * Begin a voice websocket connection
	 */
	Identify = 0,
	/**
	 * Select the voice protocol
	 */
	SelectProtocol = 1,
	/**
	 * Complete the websocket handshake
	 */
	Ready = 2,
	/**
	 * Keep the websocket connection alive
	 */
	Heartbeat = 3,
	/**
	 * Describe the session
	 */
	SessionDescription = 4,
	/**
	 * Indicate which users are speaking
	 */
	Speaking = 5,
	/**
	 * Sent to acknowledge a received client heartbeat
	 */
	HeartbeatAck = 6,
	/**
	 * Resume a connection
	 */
	Resume = 7,
	/**
	 * Time to wait between sending heartbeats in milliseconds
	 */
	Hello = 8,
	/**
	 * Acknowledge a successful session resume
	 */
	Resumed = 9,
	/**
	 * A client has connected to the voice channel
	 */
	ClientConnect = 12,
	/**
	 * A client has disconnected from the voice channel
	 */
	ClientDisconnect = 13,
}
