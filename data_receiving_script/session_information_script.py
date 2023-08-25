import websocket
import streaming_pb2
import _thread
import pyodbc
import random
import ssl
from datetime import datetime
from google.protobuf.json_format import MessageToDict
from google.protobuf.json_format import MessageToJson


def byte_string_to_mac(byte_string):
    mac = ':'.join('{:02x}'.format(byte) for byte in byte_string)
    return mac

def byte_string_to_ipv4(byte_string):
    ipv4 = '.'.join(str(byte) for byte in byte_string)
    return ipv4

def on_message(ws, message):
    # Decode Message in Serialized protobuffer
    stream_data = streaming_pb2.MsgProto()
    stream_data.ParseFromString(message)
    import apprf_pb2
    monitoring_data = apprf_pb2.apprf_session()
    monitoring_data.ParseFromString(stream_data.data)

    #Create Connection to the database
    
    connection = pyodbc.connect('Driver={ODBC Driver 18 for SQL Server};Server=tcp:network-watching.database.windows.net,1433;Database=network-watching;Uid=Adminuser;Pwd=!Trompete31012002!4;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;')
    cursor = connection.cursor()
    
    #Check whether the mandatory field "client firewall session" even exists in the message
    if monitoring_data.client_firewall_session == []:
            print("No new Sessions available")

    else:

        #Iterate over every session in the client firewall sessions array, as there can be more than one session within a message
        for session in monitoring_data.client_firewall_session:  

            #Transforming the fields from the array in variables for easier code
            mac_addr = byte_string_to_mac(session.client_mac.addr)
            client_ip = byte_string_to_ipv4(session.client_ip.addr)
            dest_ip = byte_string_to_ipv4(session.dest_ip.addr)
            ingress_type = session.ingress_type_t
            app_id = session.app_id
            app_name = session.app_name
            web_cat_id = session.web_cat_id
            web_rep_score = session.web_rep_score
            app_enforcement_status = session.app_enforcement_status
            time = datetime.now()
            time_formatted = time.strftime("%H:%M:%S")
            date = datetime.today()

            if mac_addr == "" or web_rep_score == 0:
                print("Session information not suitable!")
                print("################################################")
                print("")
            else:
                while True:
                    session_number = random.randrange(1, 2000000000)
                    cursor.execute("SELECT * FROM dbo.web_reputation WHERE session_number = "+ str(session_number)+" ;")
                    row = cursor.fetchall()
                    if row == []:
                        print("Session number generated!")
                        break

                cursor.execute("INSERT INTO dbo.web_reputation VALUES ('"+client_ip+"', '"+dest_ip+"', '"+mac_addr+"', "+str(app_id)+", '"+app_name+"', "+str(web_cat_id)+", "+str(web_rep_score)+", "+str(session_number)+", '"+str(time_formatted)+"', '"+str(date)+"');")
                connection.commit()
                print("Database updated!")
                print("################################################")
                print("")
    

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("### closed ###")

def on_open(ws):
    def run(*args):
        print("Start Streaming Data!")
    _thread.start_new_thread(run, ())


if __name__ == "__main__":
    # URL for WebSocket Connection from Streaming API page
    hostname = "internal-ui.central.arubanetworks.com"
    url = "wss://{}/streaming/api".format(hostname)
    # Construct Header for WebSocket Connection
    header = {}
    # WebSocket Key from Streaming API Page
    header["Authorization"] = "eyJhbGciOiJIUzI1NiIsInR5cGUiOiJqd3QifQ.eyJjdXN0b21lcl9pZCI6IjUwMDE1MjgiLCJjcmVhdGlvbl9kYXRlIjoxNjkwMTg1ODA1fQ.wqtHNwZ9cj5gPXo-3-5a2Iv2slbtKAPu97_xAMa86Jg"
    # Subscription TOPIC for Streaming API
    # (audit|apprf|location|monitoring|presence|security)
    header["Topic"] = "apprf"
    # Create WebSocket connection
    websocket.enableTrace(True)
    ws = websocket.WebSocketApp(url=url,
                                header=header,
                                on_message = on_message,
                                on_error = on_error,
                                on_close = on_close)
    ws.on_open = on_open
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})

