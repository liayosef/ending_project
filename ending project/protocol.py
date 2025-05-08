import json
import socket
import threading


# פרוטוקול תקשורת
class Protocol:
    # קודי הודעות
    REGISTER_CHILD = "REGISTER_CHILD"
    UPDATE_DOMAINS = "UPDATE_DOMAINS"
    GET_DOMAINS = "GET_DOMAINS"
    CHILD_STATUS = "CHILD_STATUS"
    ACK = "ACK"
    ERROR = "ERROR"

    @staticmethod
    def create_message(message_type, data=None):
        """יצירת הודעה בפרוטוקול"""
        message = {
            "type": message_type,
            "data": data
        }
        return json.dumps(message).encode('utf-8')

    @staticmethod
    def parse_message(raw_message):
        """פיענוח הודעה"""
        try:
            message = json.loads(raw_message.decode('utf-8'))
            return message["type"], message["data"]
        except Exception as e:
            print(f"Error parsing message: {e}")
            return Protocol.ERROR, str(e)

    @staticmethod
    def send_message(sock, message_type, data=None):
        """שליחת הודעה דרך socket"""
        try:

            message = Protocol.create_message(message_type, data)
            sock.send(message)
            return True
        except Exception as e:
            print(f"Error sending message: {e}")
            return False

    @staticmethod
    def receive_message(sock):
        """קבלת הודעה מ-socket"""
        try:
            raw_message = sock.recv(4096)
            return Protocol.parse_message(raw_message)
        except Exception as e:
            print(f"Error receiving message: {e}")
            return Protocol.ERROR, str(e)


# הגדרות תקשורת
COMMUNICATION_PORT = 5000  # פורט לתקשורת בין שרת למערכות ילדים