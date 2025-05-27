import json
import socket
import struct

# פורט תקשורת בין הורה לילד
COMMUNICATION_PORT = 5009


class Protocol:
    # הודעות קיימות
    REGISTER_CHILD = "register_child"
    ACK = "ack"
    UPDATE_DOMAINS = "update_domains"
    GET_DOMAINS = "get_domains"
    CHILD_STATUS = "child_status"
    BROWSING_HISTORY = "browsing_history"
    GET_HISTORY = "get_history"
    ERROR = "error"

    # הודעות חדשות למערכת רישום
    VERIFY_CHILD = "verify_child"
    VERIFY_RESPONSE = "verify_response"

    @staticmethod
    def send_message(sock, msg_type, data=None):
        """שליחת הודעה עם פרוטוקול קבוע"""
        if data is None:
            data = {}

        message = {
            "type": msg_type,
            "data": data
        }

        message_json = json.dumps(message, ensure_ascii=False)
        message_bytes = message_json.encode('utf-8')

        # שליחת אורך ההודעה ואז ההודעה עצמה
        length = struct.pack('!I', len(message_bytes))
        sock.sendall(length + message_bytes)

    @staticmethod
    def receive_message(sock):
        """קבלת הודעה עם פרוטוקול קבוע"""
        # קבלת אורך ההודעה
        length_data = sock.recv(4)
        if len(length_data) < 4:
            raise ConnectionError("Connection closed unexpectedly")

        length = struct.unpack('!I', length_data)[0]

        # קבלת ההודעה עצמה
        message_bytes = b""
        while len(message_bytes) < length:
            chunk = sock.recv(length - len(message_bytes))
            if not chunk:
                raise ConnectionError("Connection closed unexpectedly")
            message_bytes += chunk

        message_json = message_bytes.decode('utf-8')
        message = json.loads(message_json)

        return message["type"], message["data"]