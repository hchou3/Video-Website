import socketserver
import json
from pymongo import MongoClient
import hashlib
import base64
import random
import bcrypt 
import uuid
from flask import Flask

app = Flask(__name__)

def escapeInput(input):
    input=input.replace(b"&", b"&amp;").replace(b"<", b"&lt;").replace(b">", b"&gt;")
    return input

def get_next_id(collection):
    id_object=collection.find_one({})
    if id_object:
        next_id=int(id_object['last_id'])+1
        collection.update_one({},{ '$set':  {'last_id' : next_id}})
        return next_id
    else:
        collection.insert_one({'last_id' : 1})
        return 1
    
def get_next_image(collection):
    image_object=collection.find_one({})
    if image_object:
        next_id=int(image_object['id'])+1
        collection.update_one({},{ '$set':  {'id' : next_id}})
        return next_id
    else:
        collection.insert_one({'id' : 1})
        return 1

def parseHeader(data):
    data_split=data.split(b"\r\n")
    head=data_split[0].split(b" ")
    return head

def parseLength(data):
    find_key=data.find(b'Content-Length: ') + len(b'Content-Length: ')
    content_length = data[find_key: data.find(b'\r\n', find_key)]
    return content_length.decode()

def parse_type(data):
    content_type = b""
    for line in data.split(b"\r\n"):
        if b"Content-Type: " in line:
            content_type = line[len(b"Content-Type: "):]
            break
    return content_type.decode()

def parse_key(data):
    key = b""
    for line in data.split(b"\r\n"):
        if b"Sec-WebSocket-Key:" in line:
            key = line.split(b"Sec-WebSocket-Key:")[1].strip()
            break
    return key

def parse_connect(data):
    connect=b""
    for line in data.split(b'\r\n'):
        if line.startswith(b'Connection:'):
            connect = line.split(b':', 1)[1].strip()
            break
    return connect

def parse_upgrade(data):
    upgrade=b""
    for line in data.split(b'\r\n'):
        if line.startswith(b'Upgrade:'):
            upgrade = line.split(b':', 1)[1].strip()
            break
    return upgrade

def parse_cookies(data):
    cookies = {}
    cookie_line= []
    for line in data.split(b'\r\n'):
         if b'Cookie:' in line:
             cookie_line = line.split(b':', 1)[1].strip().split(b'; ')
             break
    for i in cookie_line:
        split= i.split(b'=')
        cookies[split[0]]=split[1]
    return cookies

def get_mask_and_len(data):
    mask_bit = (data & 0b10000000) >> 7# mask flag
    #print("Mask bit: ", mask_bit)
    payload_length = data & 0b01111111# payload length
    #print("Payload length bit: ", payload_length)
    return mask_bit, payload_length
    
class TCPHandler(socketserver.BaseRequestHandler):
    websocket_connections = set()
    def handle(self):
        received_data = self.request.recv(2048)
        if not received_data or received_data == []:
            return  
        #for testing: 
        print(received_data)
        header= parseHeader(received_data)
        rtype=header[1].decode()
        req_head=header[0].decode()

        if req_head=='GET':
            username=""
            if rtype == "/chat-history":
                user_msgs = [] 
                for record in user_msg_collection.find({}, {"_id": False}):
                        user_msgs.append(record)
                json_um = json.dumps(user_msgs) 
                self.request.sendall(self.get_request200(json_um, b"application/json charset=utf-8")+json_um.encode())
                
            if rtype=='/websocket':
                connection_type=parse_connect(received_data)
                upgrade=parse_upgrade(received_data)
                key=parse_key(received_data)
                sha1 = hashlib.sha1((key.decode()  + GUID).encode()).digest()
                socket= base64.b64encode(sha1)
                self.request.sendall(self.request101(upgrade, connection_type, socket))
                
                #get the payload
                username= "User" + str(random.randint(0, 1000)) 
                
                while True:
                    recent_msg = self.request.recv(1024)
                    if recent_msg==b'': 
                        self.websocket_connections.discard(self)
                        closing="10001000000000100010000000001000"
                        self.request.sendall(int(closing, 2).to_bytes((len(closing) + 7) // 8, byteorder='big')) 
                        break
                    #print("this is the first two bytes:", recent_msg)
                    first_byte = recent_msg[0]
                    second_byte = recent_msg[1]

                    opcode = first_byte & 0b00001111
                    #print("\r\nopcode:", opcode)
                    if opcode==8: 
                        self.websocket_connections.discard(self)
                        closing="10001000000000100010000000001000"
                        self.request.sendall(int(closing, 2).to_bytes((len(closing) + 7) // 8, byteorder='big')) 
                    
                    mask_bit, payload_length = get_mask_and_len(second_byte)

                    if payload_length == 126:
                        payload_length = int.from_bytes(recent_msg[2:4], byteorder='big')
                        mask_key_start = 4
                    elif payload_length == 127:
                        payload_length = int.from_bytes(recent_msg[2:10], byteorder='big')
                        mask_key_start = 10
                    else:
                        mask_key_start = 2
                    #print("\r\npayload len:", payload_length)
                    
                    if mask_bit == 1:
                        mask_key = recent_msg[mask_key_start:mask_key_start+4]
                        payload_start = mask_key_start + 4
                    else:
                        payload_start = mask_key_start
                    
                    frame_data = recent_msg[:payload_start]
                    #print("\r\nFrame Header:", frame_data)
                    payload_data = recent_msg[payload_start:payload_start + payload_length]
                    #print("\r\npayload data is initialized:", payload_data)

                    while len(payload_data) < payload_length:
                        payload_data += self.request.recv(1024)

                    full_payload = frame_data+payload_data
                    #print("\r\npayload data is complete:", full_payload)

                    payload_data_json=""     
                    
                    if mask_bit == 1:
                        unmasked_payload_data = bytearray(payload_length)
                        for i in range(payload_length):
                            unmasked_payload_data[i] = payload_data[i] ^ mask_key[i % 4]
                        payload_data_json = bytes(unmasked_payload_data)                
                    
                    #print("payload in json:", payload_data_json)    
       
                    if opcode!=8:                  
                        format_msg =json.loads(payload_data_json.decode())   
                        format_msg["username"] = username 
                        escape_comment=escapeInput(format_msg["comment"].encode())            
                        format_msg["comment"] = escape_comment.decode()
                        user_msg_collection.insert_one(format_msg) 
                        del format_msg["_id"]
                    
                        json_msg = json.dumps(format_msg).encode() 
                        print("encoded payload:", json_msg)
                    
                        first_8_bits = bin(129).lstrip("0b").zfill(8)
                        binary=b''
                        if len(json_msg) < 126:
                            binary= bin(len(json_msg))[2:].zfill(7)
                        elif 126 <= len(json_msg) and len(json_msg) < 65536:
                            binary= bin(126)[2:].zfill(7) + bin(len(json_msg))[2:].zfill(16)
                        else:
                            binary= bin(127)[2:].zfill(7)  + bin(len(json_msg))[2:].zfill(64)
                        
                        combined_8=first_8_bits + "0"+ binary
                        combined_encoded=int(combined_8, 2).to_bytes((len(combined_8) + 7) // 8, byteorder='big')
                        new_frame = combined_encoded+ json_msg
                        if self not in self.websocket_connections:
                            self.websocket_connections.add(self)
                        for connection in self.websocket_connections:
                            connection.request.sendall(new_frame)  
                    else:
                        self.websocket_connections.discard(self)
                        closing="10001000000000100010000000001000"
                        self.request.sendall(int(closing, 2).to_bytes((len(closing) + 7) // 8, byteorder='big')) 
                        break
                        
            if rtype=='/users':
                user_data=users_collection.find({}, {'_id': False})
                user_data=list(user_data)
                user_data_encoded=json.dumps(user_data)
                self.request.sendall(self.get_request200(user_data_encoded, b"application/json")+user_data_encoded.encode())
            elif '/users/' in rtype:
                user_id = int(rtype.split("/users/")[1]) 
                user = users_collection.find_one({"id": user_id}, {"_id": False})
                if user:
                    user_json=json.dumps(user)
                    self.request.sendall(self.get_request200(user_json, b"application/json")+user_json.encode())
                else:
                   self.request.sendall(self.request404(b"Sorry! User does not exist.")) 
            if rtype=='/':
                 file=f_read("index.html")
                 cookie_info=parse_cookies(received_data)
                 print(cookie_info)
                 
                 cookie_num=1
                 new_cookie_num=1
                 post_user=""
                 get_auth=""
                 if b'Visited'in cookie_info:
                        cookie_num= int(cookie_info[b'Visited'].decode())
                        new_cookie_num= int(cookie_info[b'Visited'].decode())+1
                 if b'User' in cookie_info:
                        post_user= str(cookie_info[b'User'].decode())
                 if b"AuthToken" in cookie_info:
                        get_auth= cookie_info[b'AuthToken'].decode()
                        
                        
                 updated_file=file.replace("{{cookie_count}}", "<h1>Number of page visits: " + str(cookie_num)+"</h1>")
                 
                 #document = user_token_collection.find_one({"UsernameToken": post_user})
                 print(get_auth)
                 
                 if get_auth != "":
                    updated_file=updated_file.replace("{{user_visits}}", "<h1>Welcome, " + post_user+"!</h1>")
                 else:
                    updated_file=updated_file.replace("{{user_visits}}", "<h1>Welcome, !</h1>")
                    
                 self.request.sendall(self.cookie_request200(updated_file, b"text/html", new_cookie_num)+updated_file.encode())
            elif rtype== '/index.html':
                file=f_read_b("index.html")
                self.request.sendall(self.get_request200(file , b"text/html; charset=utf-8")+file)
            elif rtype=='/style.css':
                file=f_read_b("style.css")
                self.request.sendall(self.get_request200(file , b"text/css; charset=utf-8")+file)
            elif rtype=='/functions.js':
                file=f_read_b("functions.js")
                self.request.sendall(self.get_request200(file , b"text/javascript; charset=utf-8")+file)
            elif "/image/" in rtype:
                img_get= rtype[rtype.find('/image/') + len('/image/'):]
                img_get= img_get.replace("/", "")
                file=f_read_b("image/"+img_get)
                self.request.sendall(self.get_request200(file, b"image/jpeg")+file)
            else:
                self.request.sendall(self.request404(b"Sorry! Page does not exist."))
        if req_head=='POST':                
            if rtype == "/register":
                credentials= get_user_and_pwd(received_data)
                print(credentials)
                username = str(credentials["username"])             
                password = bcrypt.hashpw(credentials["password"].encode(),bcrypt.gensalt())
                user_pwds_collection.insert_one({"Username" : username, "Password" : password})
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 19\r\n\r\nAccount Registered!")
                
            if rtype == "/login":
                credentials= get_user_and_pwd(received_data)
                print(credentials)
                username = str(credentials["username"])  
                user_login = credentials["password"]
                get_username = user_pwds_collection.find_one({"Username":username})
                print(get_username["Password"])
                print(user_login)
                if bcrypt.checkpw(user_login.encode('utf-8') ,get_username["Password"]):
                    token = str(uuid.uuid4())
                    tokenhash =  bcrypt.hashpw(token.encode("utf-8"),bcrypt.gensalt())
                    user_token_collection.insert_one({"UsernameToken":username, "Token":tokenhash})
                    print("authetication token:",token)
                    print("token with hash:", tokenhash)
                    self.request.sendall(self.token_request200(b"text/html", username, token, "Login Success!"))
                else:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 13\r\n\r\nLogin Failed.")
                    
            if rtype=='/users':
                decoded=received_data.decode()
                double=decoded.find('\r\n\r\n')
                data_msg=decoded[double + len('\r\n\r\n') :]
                email=json.loads(data_msg)
                email["id"]=get_next_id(users_id_collection)
                users_collection.insert_one(email) 
                post_msg_json=json.dumps(users_collection.find_one(email), {"_id": False}).encode()
                self.request.sendall(self.request201(post_msg_json, b"application/json")+post_msg_json)
            if rtype == "/image-upload" and b"multipart/form-data" in received_data:
                image_form=received_data[received_data.find(b'\r\n\r\n') + len(b'\r\n\r\n') :]
                image_form_head= received_data[received_data.find(b'\r\n') + len(b'\r\n') : received_data.find(b'\r\n\r\n')]
                get_type=parse_type(image_form_head)#print("get type:", get_type)
                image_content_length=int(parseLength(received_data))#print("Content-Length:",image_content_length)

                if b"Content-Length" in received_data:
                    image_buffer=image_form
                    image_content_len=image_content_length
                while len(image_buffer)  < image_content_len:
                    image_buffer += self.request.recv(1024)
                image_form = image_buffer
                print(image_form)
                
                imgcmmt =get_image_w_comments(get_type, image_form)
                comments_data = parse_data(imgcmmt[0])
                img_data = parse_data(imgcmmt[1])
                esc_comment = escapeInput(comments_data)
                image_collection.insert_one({"id": get_next_image(image_collection)})
                img_name = "image/image" + str(getImageID(image_collection)) + ".jpg" 
                image_comments_collection.insert_one({img_name: esc_comment.decode()})
                f_write(img_name, img_data)
                load_temp= load_thread(image_comments_collection, "templ1.html", "{{top}}", "{{bottom}}") 
                f_write("index.html", load_temp)
                self.request.sendall(b"HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\nLocation: /\r\n\r\n")
        if req_head=='DELETE':
                del_id=int(rtype.split("/users/")[1])
                delete= users_collection.delete_one({"id": del_id  })
                if delete.deleted_count() > 0:
                    self.request.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                else:
                    self.request.sendall(self.request404(b"Sorry! User does not exist."))
        if req_head=='PUT':
                put_id=int(rtype.split("/users/")[1])
                decoded=received_data.decode()
                put=decoded.find('\r\n\r\n')
                put_user=json.loads(decoded[put + len('\r\n\r\n') : ])
                user_info=users_collection.find_one({"id": put_id})
                if user_info:
                    users_collection.update_one({"id": put_id},{"$set": {"email": put_user["email"], "username": put_user["username"]}})
                    new_user_info=users_collection.find_one({"email": put_user["email"], "username": put_user["username"]}, {"_id": False})
                    new_user_info_json=json.dumps(new_user_info)
                    self.request.sendall(self.get_request200(new_user_info_json, b"application/json")+new_user_info_json.encode())
                else:
                    self.request.sendall(self.request404(b"Sorry! User does not exist."))
                    

    def request404(self, err_msg):
        return_msg=b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: "
        return_msg+=str(len(err_msg)).encode()
        return_msg+=b"\r\n\r\n"
        return_msg+=err_msg
        return return_msg
    def get_request200(self, data, type):
        msg= b"HTTP/1.1 200 OK\r\nContent-Type: "
        msg+=type
        msg+=b"\r\nX-Content-Type-Options: nosniff\r\nContent-Length: "
        msg+=str(len(data)).encode()
        msg+=b"\r\n\r\n"
        return msg
    #self.request.sendall(self.cookie_request200(updated_file, b"text/html; charset=utf-8", cookie_num)+updated_file.encode())
    def cookie_request200(self, data, type, visits):
        msg= b"HTTP/1.1 200 OK\r\nSet-Cookie: Visited="
        msg+=str(visits).encode()
        msg+=b"; Max-Age=3600"
        msg+=b"\r\nContent-Type: "
        msg+=type
        msg+=b"\r\nX-Content-Type-Options: nosniff\r\nContent-Length: "
        msg+=str(len(data)).encode()
        msg+=b"\r\n\r\n"
        print(msg)
        return msg
    
    def token_request200(self, type, user, tok, data):
        msg= b"HTTP/1.1 200 OK\r\nSet-Cookie: AuthToken="
        msg+= tok.encode()
        msg+= b"; Max-Age=3600; HttpOnly;\r\nSet-Cookie: User="
        msg+= user.encode()
        msg+= b";\r\nContent-Type: "
        msg+= type 
        msg+= b"\r\nX-Content-Type-Options: nosniff\r\nContent-Length: "
        msg+= str(len(data)).encode()
        msg+= b"\r\n\r\n"
        msg+= data.encode()
        print(msg)
        return msg
    
    def request201(self, data, type):
        msg = b"HTTP/1.1 201 CREATED\r\nContent-Type: "
        msg+=type
        msg+= b"\r\nX-Content-Type-Options: nosniff\r\nContent-Length: "
        msg+= str(len(data)).encode()
        msg+= b'\r\n\r\n'
        return msg
    def request101(self, upgrade, type, socket):
        msg= b"HTTP/1.1 101 Switching Protocols\r\n"
        msg+= b"Upgrade: "
        msg+= upgrade
        msg+= b"\r\nConnection: "
        msg+= type
        msg+= b"\r\nSec-WebSocket-Accept: " 
        msg+=socket
        msg+= b'\r\n\r\n'
        return msg
    
def f_read_b(file):
    with open(file, 'rb') as f:
        return f.read()
    
def f_write(file, output):
    with open(file, 'wb') as f:
        return f.write(output)
    
def f_add(file, output):
    with open(file,'ab') as f:
        return f.write(output)
    
def f_read(file):
     with open(file,'r') as f:
        return f.read()
    
def parse_data(data):
    double=data.find(b'\r\n\r\n')
    new_data=data[double + len(b'\r\n\r\n') : ]
    return new_data.rstrip(b'\r\n')


def generateNextID(ID_collection):
    filter = {"id": getImageID(ID_collection)}
    increasedValue =  {"id": 1}
    ID_collection.update_one(filter, {"$inc": increasedValue}) 
    return ID_collection.find_one({})["id"]

def getImageID(ID_collection):
    if ID_collection.count_documents({}) == 0: 
        ID_collection.insert_one({"id": 0}) 

    return ID_collection.find_one({})["id"]

def load_thread(comments, layout, header, footer):
    form=f_read(layout)

    posts = []
    for record in comments.find({}, {"_id": False}):
        posts.append(record)
    json_posts=json.dumps(posts)
    img_comments_data = json.loads(json_posts)

    thread=form[form.find(header): form.find(footer)+len(footer)] 

    layout_bytes = "" 
    for img_comment_line in img_comments_data:
        images = []
        for img, cmmt in img_comment_line.items():
            bytes = thread.replace("{{image}}", f'"{img}" class="my_image"').replace("{{comment}}", cmmt).strip(header).strip(footer)
            images.append(bytes)
        layout_bytes += "\r\n\r\n".join(images)

    send_layout=f_read_b("templ1.html").replace(thread.encode(), layout_bytes.encode())
    return send_layout

def get_image_w_comments(ctype, data):
    parse="--"
    parse+=ctype[ctype.find("multipart/form-data; boundary=")+ len("multipart/form-data; boundary="):]
    bounds=data.split(parse.encode())
    new_bounds=bounds[1:-1]

    return new_bounds

def get_user_and_pwd(data):
    credentials = {}
    register_body= data[data.find(b'\r\n') + len(b'\r\n') : data.find(b'--\r\n')]

    username = register_body.split(b"name=\"username\"\r\n\r\n")[1].split(b"\r\n")[0].decode()
    password = register_body.split(b"name=\"password\"\r\n\r\n")[1].split(b"\r\n")[0].decode()
    credentials["username"] = username
    credentials["password"] = password
    
    return credentials
    

@app.route('/deleteOne', methods=['POST'])
def delete_one():
    first_doc = user_token_collection.find_one()
    if first_doc:
        user_token_collection.delete_one({'_id': first_doc['_id']})    
    return "OK"
if __name__ == "__main__":
    mongo_client = MongoClient("mongo")
    db = mongo_client["cse312"]
    chat_collection = db["chat"]

    users_collection=db["users"]
    users_id_collection=db["users_ids"]

    image_collection=db["image_ids"]
    image_comments_collection=db["img_cmmt"]

    user_msg_collection=db["user_msg"]
    user_pwds_collection=db["user_pwd"]
    user_token_collection=db["user_token"]
    ###Testing##
    #image_board=[]
    #for record in image_comments_collection.find({}, {"_id": False}):
        #image_board.append(record)
    #load_board=json.dumps(image_board)
    #print("image-comments-db",json.loads(load_board))

    #images_=[]
    #for record in image_collection.find({}, {"_id": False}):
        #images_.append(record)
    #load_IDs=json.dumps(images_)
    #print("images-db",json.loads(load_IDs))
    
    usernames_passwords_=[]
    for record in user_pwds_collection.find({}, {"_id": False}):
        usernames_passwords_.append(record)
    print("user-pwd-db",usernames_passwords_)
    

    usernames_tokens_=[]
    for record in user_token_collection.find({}, {"_id": False}):
        usernames_tokens_.append(record)
    print("user-tokens-db",usernames_tokens_)
    
    #generate hash
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    
    HOST, PORT = "0.0.0.0", 8080
    # Create the server, binding to localhost on port 8080
    server= socketserver.ThreadingTCPServer((HOST, PORT), TCPHandler)
    server.serve_forever()
