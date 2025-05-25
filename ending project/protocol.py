import json
import struct

# פורט התקשורת בין השרת לקליינט
COMMUNICATION_PORT = 8888


class Protocol:
    """
    פרוטוקול תקשורת בין שרת ההורים וקליינט הילד
    """
    # סוגי הודעות
    REGISTER_CHILD = 1  # רישום ילד חדש
    ACK = 2  # אישור
    ERROR = 3  # שגיאה
    GET_DOMAINS = 4  # בקשה לקבלת דומיינים חסומים
    UPDATE_DOMAINS = 5  # עדכון דומיינים חסומים
    CHILD_STATUS = 6  # עדכון סטטוס ילד
    BROWSING_HISTORY = 7  # שליחת היסטוריית גלישה
    GET_HISTORY = 8  # בקשה לקבלת היסטוריית גלישה

    @staticmethod
    def send_message(sock, msg_type, data=None):
        """
        שליחת הודעה לצד השני
        Args:
            sock: סוקט להתחברות
            msg_type: סוג ההודעה
            data: מילון עם מידע נוסף (אופציונלי)
        """
        # אם אין מידע, נאתחל מילון ריק
        if data is None:
            data = {}

        # המרת המידע ל-JSON
        json_data = json.dumps(data).encode('utf-8')

        # בניית הודעה: סוג הודעה (4 בתים) + אורך מידע (4 בתים) + מידע
        header = struct.pack('!II', msg_type, len(json_data))

        # שליחת ההודעה
        sock.sendall(header + json_data)

    @staticmethod
    def receive_message(sock):
        """
        קבלת הודעה מהצד השני
        Args:
            sock: סוקט להתחברות
        Returns:
            tuple: (סוג ההודעה, המידע כמילון)
        """
        # קריאת header (8 בתים)
        header = sock.recv(8)
        if len(header) != 8:
            raise ConnectionError("התקבל header לא תקין")

        # פירוק ה-header
        msg_type, data_len = struct.unpack('!II', header)

        # קריאת המידע
        data = b''
        while len(data) < data_len:
            chunk = sock.recv(min(4096, data_len - len(data)))
            if not chunk:
                raise ConnectionError("החיבור נסגר")
            data += chunk

        # המרת JSON לפייתון
        if data:
            return msg_type, json.loads(data.decode('utf-8'))
        else:
            return msg_type, {}