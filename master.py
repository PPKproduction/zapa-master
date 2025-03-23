import random
import signal
import typing
import mysql
from mysql.connector import connect, cursor
from mysql import connector
from unidecode import unidecode
import yaml, json
import board
import busio
import digitalio
from adafruit_rfm9x import RFM9x, _RH_FLAGS_ACK, _RH_BROADCAST_ADDRESS, _RH_FLAGS_RETRY
import time
import sys
import logging
import logging.config
from Crypto.Cipher import AES
from datetime import datetime

MASTER_ADDR = 0x00
UID_LEN = 10
QUOTA_LEN = 4
MAX_NAME_LEN = 30
PERSON_REQUEST_TAG = ord('R')
QUOTA_UPDATE_TAG = ord('U')
global src

with open("/opt/updater/settings.json", 'r') as openfile:
    UpdaterSettings = json.load(openfile)
openfile.close()


class PersonRequest:
    @staticmethod
    def payload_is(payload: bytes):
        return len(payload) > 0 and payload[0] == PERSON_REQUEST_TAG

    def __init__(self, from_address: int, payload: bytes) -> None:
        assert len(payload) == 1 + UID_LEN
        assert payload[0] == PERSON_REQUEST_TAG

        self.from_address = from_address
        self.uid = bytes(payload[1:])

    def __str__(self) -> str:
        return f'PersonRequest: from_address={self.from_address}, uid={self.uid}'


class QuotaUpdate:
    @staticmethod
    def payload_is(payload: bytes):
        return len(payload) > 0 and payload[0] == QUOTA_UPDATE_TAG

    def __init__(self, from_address: int, payload: bytes) -> None:
        assert len(payload) == 1 + UID_LEN + QUOTA_LEN
        assert payload[0] == QUOTA_UPDATE_TAG
        payload = payload[1:]
        quota_diff_raw = payload[UID_LEN:]

        self.from_address = from_address
        self.uid = bytes(payload[:UID_LEN])
        self.quota_diff = int.from_bytes(bytes=quota_diff_raw, byteorder='little', signed=False)

    def __str__(self) -> str:
        return f'QuotaUpdate: from_address={self.from_address}, uid={self.uid}, quota_diff={self.quota_diff}'


class Person:
    def __init__(self, uid: bytes, name: str, quota: int) -> None:
        self.uid = uid
        self.name = name
        self.quota = quota

    def __str__(self) -> str:
        return f'Person: uid={self.uid}, name={self.name}, quota={self.quota}'


class Daemon:
    def __init__(self, config_file) -> None:
        self.stopped = False
        self.slaves = set()

        _l.info('Loading configruation from {}', config_file)
        with open(config_file, 'r') as f:
            conf = yaml.load(f, yaml.Loader)
        if 'secret' in conf:
            try:
                secret = conf['secret'].encode('ascii')
            except UnicodeEncodeError:
                _l.critical('Secret contains non-ASCII characters. Terminating.')
                sys.exit(78)
            if len(secret) not in AES.key_size:
                _l.critical('Incorrect secret length ({}). Must be one of {}. Terminating.', len(secret), AES.key_size)
                sys.exit(78)
            self.cipher = AES.new(secret, AES.MODE_ECB)
        else:
            _l.warning(
                'No secret present in the configuration file. Will use default key of 0000000000000000 (16 0-bytes).')
            self.cipher = AES.new(bytes([0] * 16), AES.MODE_ECB)

        if 'slaves' in conf:
            slaves = conf['slaves']
            if not isinstance(slaves, list):
                _l.critical('The value of \'slaves\' key in the configuration file is not a list. Terminating.')
                sys.exit(78)
            for i, slave in enumerate(slaves):
                i += 1
                si = str(i)
                if si.endswith('11') or si.endswith('12') or si.endswith('13'):
                    suffix = 'th'
                elif si.endswith('1'):
                    suffix = 'st'
                elif si.endswith('2'):
                    suffix = 'nd'
                elif si.endswith('3'):
                    suffix = 'rd'
                else:
                    suffix = 'th'
                try:
                    slave = int(slave)
                except:
                    _l.critical('{}{} slave address \'{}\' is malformed. Terminating.', i, suffix, slave)
                    sys.exit(78)
                if slave < 1:
                    _l.critical('{}{} slave address {} ({:#04x}) is less than 1. Terminating.', i, suffix, slave, slave)
                    sys.exit(78)
                if slave >= 255:
                    _l.critical('{}{} slave address {} ({:#04x}) is greater than or equal to 255 (0xff). Terminating.',
                                i, suffix, slave, slave)
                    sys.exit(78)
                _l.info('Adding slave {:#04x} to managed slaves.', slave)
                if slave in self.slaves:
                    _l.warning('Duplicate slaves {} ({:#04x}).', slave, slave)
                self.slaves.add(slave)

        if 'ack_delay' in conf:
            try:
                ack_delay = float(conf['ack_delay'])
            except:
                _l.critical('ack_delay is malformed. Terminating.')
                sys.exit(78)
            if ack_delay < 0:
                _l.critical('ack_delay is negative. Terminating.')
                sys.exit(78)
            _l.info('Using ack_delay={}.', ack_delay)
        else:
            _l.info('No ack_delay specified, using default of 0.1.')
            ack_delay = 0.1

        if 'ack_retries' in conf:
            try:
                ack_retries = int(conf['ack_retries'])
            except:
                _l.critical('ack_retries is malformed. Terminating.')
                sys.exit(78)
            if ack_retries < 0:
                _l.critical('ack_retries is negative. Terminating.')
                sys.exit(78)
            _l.info('Using ack_retries={}.', ack_retries)
        else:
            _l.info('No ack_retries specified, using default of 8.')
            ack_retries = 8

        if 'ack_wait' in conf:
            try:
                ack_wait = float(conf['ack_wait'])
            except:
                _l.critical('ack_wait is malformed. Terminating.')
                sys.exit(78)
            if ack_wait < 0:
                _l.critical('ack_wait is negative. Terminating.')
                sys.exit(78)
            _l.info('Using ack_wait={}.', ack_wait)
        else:
            _l.info('No ack_wait specified, using default of 0.25.')
            ack_wait = 0.25

        if 'tx_power' in conf:
            try:
                tx_power = int(conf['tx_power'])
            except:
                _l.critical('tx_power is malformed. Terminating.')
                sys.exit(78)
            if tx_power < 5:
                _l.critical('tx_power is less than 5. Terminating.')
                sys.exit(78)
            if tx_power > 20:
                _l.critical('tx_power is greater than 20. Terminating.')
                sys.exit(78)
            _l.info('Using tx_power={}.', tx_power)
        else:
            _l.info('No tx_power specified, using default of 13.')
            tx_power = 13

        self.radio = RFM9x(
            spi=busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO),
            cs=digitalio.DigitalInOut(board.CE1),
            reset=digitalio.DigitalInOut(board.D25),
            frequency=868,
            high_power=True,
            crc=True
        )
        self.radio.node = MASTER_ADDR
        # delay before an ack is sent back
        self.radio.ack_delay = ack_delay
        # number of retransmissions before giving up on receiving an ack
        self.radio.ack_retries = ack_retries
        # how long to wait for an ack before retransmitting - actually is chosen randomly between this and 2 * this value
        self.radio.ack_wait = ack_wait
        self.radio.tx_power = tx_power

        self.crypt = True

        # mock database
        self.people: typing.MutableMapping[bytes, Person] = dict()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def handle_packet(self, packet):
        global src
        _l.debug('Received raw packet: {}', packet)
        dest = packet[0]
        src = packet[1]
        _id = packet[2]
        flags = packet[3]
        payload = packet[4:]

        # do not Ack unknown slaves
        if src not in self.slaves:
            _l.debug('Slave {:#04x} not among managed slaves, ignoring.', src)
            return
        # re-implement a bit of receive() from adafruit_rfm9x
        if ((flags & _RH_FLAGS_ACK) == 0) and (dest != _RH_BROADCAST_ADDRESS):
            # delay before sending Ack to give receiver a chance to get ready
            if self.radio.ack_delay is not None:
                time.sleep(self.radio.ack_delay)
            # send ACK packet to sender (data is b'!')
            _l.debug('Sending ack: dest={}, src={}, id={}, flags={:b}', src, dest, _id, flags | _RH_FLAGS_ACK)
            self.radio.send(
                b"!",
                destination=src,
                node=dest,
                identifier=_id,
                flags=(flags | _RH_FLAGS_ACK),
            )
            # reject Retries if we have seen this idetifier from this source before
            if (self.radio.seen_ids[src] == _id) and (flags & _RH_FLAGS_RETRY):
                # packet = None
                return
            else:  # save the packet identifier for this source
                self.radio.seen_ids[src] = _id

        # decrypt payload
        if self.crypt:
            payload = self.decrypt(payload)

        # process payload
        self.handle_payload(src, payload)

    def handle_payload(self, from_address: int, payload: bytes):
        if PersonRequest.payload_is(payload):
            # Person request
            pr = PersonRequest(from_address, payload)
            self.handle_person_request(pr)
        elif QuotaUpdate.payload_is(payload):
            # quota update
            qu = QuotaUpdate(from_address, payload)
            self.handle_quota_update(qu)
        else:
            _l.error('Unrecognized payload: {}', payload)

    def handle_person_request(self, pr: PersonRequest):
        _l.info('Handling person request: {}', pr)
        person = self.get_person(pr.uid)
        # wait a bit to give the slave time to enter receive mode just in case
        time.sleep(.25)
        self.send_person(pr.from_address, person)

    def handle_quota_update(self, qu: QuotaUpdate):
        _l.info('Handling quota update: {}', qu)
        self.update_quota(qu.uid, qu.quota_diff)

    def get_person(self, uid) -> Person:
        userdatabase.commit()
        l_uid = str(uid)
        l_uid = l_uid.strip('b')

        # l_uid = l_uid.strip("b")
        _l.info('Retrieving person with UID={} from DB.', l_uid)
        sql = "SELECT Name, Surname, Remaining FROM UserList WHERE TAGID = " + str(l_uid)
        curs.execute(sql)
        result = curs.fetchone()
        _l.info('{}', result)

        data = []
        if result is not None:
            Name = unidecode(result[0])
            Surname = unidecode(result[1])
            Quota = result[2]
            Show_name = Name[0] + "." + Surname
            data = Person(
                uid,
                Show_name,
                Quota)
        else:
            data = Person(
                uid,
                "I.USER",
                0000)
        person = data
        _l.debug('Retrieved person {}.', person)
        return person

    def send_person(self, to_address: int, person: Person):
        _l.info('Sending person {}.', person)
        data = (person.uid +
                person.quota.to_bytes(length=4, byteorder='little', signed=False) +
                person.name.encode('ascii'))
        self.send(to_address, data)

    def update_quota(self, uid: bytes, quota_diff: int):
        global src

        _l.info('Changing quota by {} for person with TAGID={} in DB.', quota_diff, uid)
        if quota_diff == 0:
            _l.info('quota diff = 0, update not needed')
            return

        l_uid = str(uid)
        l_uid = l_uid.strip("b")
        l_uid = l_uid.strip("'")
        _l.error(l_uid)
        sql = f"SELECT Remaining, Name, Surname FROM UserList WHERE TAGID = '{str(l_uid)}'"

        try:
            curs.execute(sql)
            result = curs.fetchone()
        except Exception as e:
            _l.error(f"error: {str(e)}")


        if result is None:
            _l.error("TAGID {} not in database, cannot update quota.", uid)
            return
        _l.info('Old quota {}L', result[0])
        newquota = result[0] - quota_diff
        _l.info('NEW quota {}L', newquota)
        if newquota < 0:
            newquota = 0
        # sql = 'update UserList SET Remaining = {qdiff}  where UID = "{u}"'.format(qdiff = str(newquota),u = str(l_uid))
        sql = "UPDATE UserList SET Remaining = '{quota}' WHERE TAGID = '{TAGID}'".format(quota=str(newquota),
                                                                                       TAGID=str(l_uid))
        curs.execute(sql)
        userdatabase.commit()
        branch = UpdaterSettings["branch_office_id"]
        curdate = datetime.now().date()
        curtime = datetime.now().time()
        sql = f"INSERT INTO WaterUsage (TAGID, Date, Time, UsedWater, ADDR, SentFlag) VALUES ('{str(l_uid)}', '{curdate}','{curtime}', {quota_diff},'{src}', TRUE )"
        curs.execute(sql)
        userdatabase.commit()
        sql = f"INSERT INTO WaterUsageExt (TAGID, Date, Time, UsedWater,BranchID, ADDR) VALUES ('{str(l_uid)}', '{curdate}','{curtime}', {quota_diff},'{branch}','{src}')"
        if CommitToExtDB(sql) == 1:
            sql = f"UPDATE WaterUsage SET SentFlag = TRUE WHERE Date = '{curdate}' AND Time = '{curtime}'"
            curs.execute(sql)
            userdatabase.commit()

    def send(self, to_address: int, data: bytes):
        _l.debug('Sending data {}', data)
        if self.crypt:
            data = self.encrypt(data)
        _l.debug('Sending raw data {}', data)
        self.radio.destination = to_address
        if self.radio.send_with_ack(data):
            _l.debug('Data acknowledged.')
        else:
            _l.warning('Data not acknowledged.')

    def encrypt(self, data: bytes) -> bytes:
        blocks = []
        k = 0  # block index
        j = 0  # original message index
        while k * self.cipher.block_size < len(data) + 1:
            blocks.append(bytearray([0] * self.cipher.block_size))
            h = 0  # block content index
            if k == 0:
                # put payload length into the first byte of the first block
                blocks[k][h] = len(data)
                h += 1
            while h < self.cipher.block_size:
                # copy each payload byte into blocks, pad with 0 if necessary
                if j < len(data):
                    blocks[k][h] = data[j]
                    j += 1
                else:
                    blocks[k][h] = 0
                h += 1
            k += 1
        _l.debug('Data split into blocks: {}', blocks)
        data = b''.join(blocks)
        _l.debug('Data to encrypt: {}', data)
        data = self.cipher.encrypt(b''.join(blocks))
        _l.debug('Encrypted data: {}', data)
        return data

    def decrypt(self, data: bytes) -> bytes:
        data = self.cipher.decrypt(data)
        _l.debug('Raw decrypted data: {}', data)
        # first byte is the data length, excluding this first byte
        data_length = data[0]
        _l.debug('Data length: {}', data_length)
        data = data[1:data_length + 1]
        _l.debug('Trimmed decrypted data: {}', data)
        return data

    def run(self):
        _l.info('Listening for slaves...')
        while not self.stopped:
            packet = self.radio.receive(with_header=True, with_ack=False)
            if packet is None:
                continue
            self.handle_packet(packet)
        _l.info('Terminated.')

    def stop(self, sig, frame):
        self.stopped = True


def CommitToExtDB(SQLstatement):
    try:
        externalDB = mysql.connector.connect(
            user=UpdaterSettings["EXTDBuser"],
            password=UpdaterSettings["EXTDBpassword"],
            database=UpdaterSettings["EXTDBdb"],
            host=UpdaterSettings["EXTDBhostname"],
            port=UpdaterSettings["EXTDBport"]
        )
        extcursor = externalDB.cursor()
        extcursor.execute(SQLstatement)
        externalDB.commit()
        extcursor.close()
        externalDB.close()
        return 1
    except Exception as e:
        print(e)
        return 0


# utility class for easy logging with {}-style formatting
class _l:
    @staticmethod
    def debug(fmt, /, *args, **kwargs):
        logging.debug(_l(fmt, *args, **kwargs))

    @staticmethod
    def info(fmt, /, *args, **kwargs):
        logging.info(_l(fmt, *args, **kwargs))

    @staticmethod
    def warning(fmt, /, *args, **kwargs):
        logging.warning(_l(fmt, *args, **kwargs))

    @staticmethod
    def error(fmt, /, *args, **kwargs):
        logging.error(_l(fmt, *args, **kwargs))

    @staticmethod
    def critical(fmt, /, *args, **kwargs):
        logging.critical(_l(fmt, *args, **kwargs))

    @staticmethod
    def exception(fmt, /, *args, **kwargs):
        logging.exception(_l(fmt, *args, **kwargs))

    def __init__(self, fmt, /, *args, **kwargs):
        self.fmt = fmt
        self.args = args
        self.kwargs = kwargs

    def __str__(self):
        return self.fmt.format(*self.args, **self.kwargs)


if __name__ == '__main__':
    f = logging.Formatter(
        fmt='[{asctime}] {levelname:<8s} - {threadName} - {message}',
        style='{'
    )

    h = logging.StreamHandler(stream=sys.stderr)
    h.setLevel(logging.INFO)
    h.setFormatter(f)

    logging.root.level = logging.DEBUG
    for h in logging.root.handlers:
        logging.root.removeHandler(h)
    logging.root.addHandler(h)

    _l.info('Startup')
    _l.info('Args: {}', sys.argv)

    try:
        userdatabase = mysql.connector.connect(
            user=UpdaterSettings["DBuser"],
            password=UpdaterSettings["DBpassword"],
            database=UpdaterSettings["DB"]
        )
        curs = userdatabase.cursor()

    except:
        _l.error('Database Error')
    with Daemon(sys.argv[1]) as d:
        signal.signal(signal.SIGINT, d.stop)
        signal.signal(signal.SIGTERM, d.stop)
        d.run()
