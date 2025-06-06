# -*- coding: utf-8 -*-
from flask import Flask, render_template_string, request, redirect, url_for, session
import paramiko
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.rsakey import RSAKey
import os
import logging
import io
import socket # Để bắt socket.timeout

# Cấu hình logging cơ bản
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Cần thiết cho việc sử dụng session trong Flask
app.secret_key = os.urandom(24)

# Biến toàn cục để lưu trữ các SSH client đang hoạt động
active_ssh_clients = {}

# --- HTML Template ---
INDEX_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH Web Client</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { 
            font-family: 'Inter', sans-serif; 
            overscroll-behavior-y: none;
        }
        .container { max-width: 800px; }
        pre::-webkit-scrollbar { width: 8px; }
        pre::-webkit-scrollbar-track { background: #f1f1f1; border-radius: 10px; }
        pre::-webkit-scrollbar-thumb { background: #888; border-radius: 10px; }
        pre::-webkit-scrollbar-thumb:hover { background: #555; }
        textarea { resize: vertical; }
        /* Đảm bảo pre hiển thị đúng dòng mới và cuộn */
        pre {
            white-space: pre-wrap;       /* CSS 3 */
            white-space: -moz-pre-wrap;  /* Mozilla, since 1999 */
            white-space: -pre-wrap;      /* Opera 4-6 */
            white-space: -o-pre-wrap;    /* Opera 7 */
            word-wrap: break-word;       /* Internet Explorer 5.5+ */
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center p-4">
    <div class="container w-full bg-white shadow-xl rounded-lg p-6 md:p-8">
        <h1 class="text-3xl font-bold text-center text-blue-600 mb-6">SSH Web Client</h1>

        <!-- Trạng thái kết nối -->
        {% if session.get('active_connection_target') %}
            <div class="bg-green-100 border-l-4 border-green-500 text-green-700 p-4 rounded-md mb-4" role="alert">
                <p class="font-bold">Đang kết nối tới:</p>
                <p>{{ session.get('active_connection_target') }}
                   (<a href="{{ url_for('disconnect_ssh') }}" class="text-red-600 hover:text-red-800 font-semibold underline">Ngắt kết nối & Xóa Output</a>)
                </p>
            </div>
        {% else %}
            <div class="bg-yellow-100 border-l-4 border-yellow-500 text-yellow-700 p-4 rounded-md mb-4" role="alert">
                <p class="font-bold">Trạng thái: Chưa kết nối.</p>
            </div>
        {% endif %}

        <!-- Hiển thị thông báo lỗi chung -->
        {% if error %}
            <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 rounded-md mb-4" role="alert">
                <p class="font-bold">Lỗi chung!</p>
                <p>{{ error }}</p>
            </div>
        {% endif %}
        
        <!-- Hiển thị thông báo thành công/tin nhắn -->
        {% if message %}
            <div class="bg-blue-100 border-l-4 border-blue-500 text-blue-700 p-4 rounded-md mb-4" role="alert">
                <p class="font-bold">Thông báo:</p>
                <p>{{ message }}</p>
            </div>
        {% endif %}

        <form method="POST" action="{{ url_for('handle_ssh_command') }}" class="space-y-6" enctype="multipart/form-data">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <label for="host" class="block text-sm font-medium text-gray-700">Máy chủ (Host/IP):</label>
                    <input type="text" name="host" id="host" value="{{ session.get('host', '') }}" required
                           class="mt-1 block w-full px-3 py-2 bg-white border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                </div>
                <div>
                    <label for="port" class="block text-sm font-medium text-gray-700">Cổng (Port):</label>
                    <input type="number" name="port" id="port" value="{{ session.get('port', 22) }}" required
                           class="mt-1 block w-full px-3 py-2 bg-white border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                </div>
            </div>
            <div>
                <label for="username" class="block text-sm font-medium text-gray-700">Tên đăng nhập:</label>
                <input type="text" name="username" id="username" value="{{ session.get('username', '') }}" required
                       class="mt-1 block w-full px-3 py-2 bg-white border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
            </div>

            <div class="border-t border-gray-200 pt-6 mt-6">
                <h2 class="text-lg font-medium text-gray-900 mb-1">Xác thực bằng SSH Key</h2>
                <p class="text-xs text-gray-500 mb-3">Ưu tiên sử dụng nếu được cung cấp. Chỉ cần cung cấp một lần cho mỗi phiên kết nối.</p>
                <div>
                    <label for="private_key_file" class="block text-sm font-medium text-gray-700">Tệp khóa riêng tư (Private Key File):</label>
                    <input type="file" name="private_key_file" id="private_key_file"
                           class="mt-1 block w-full text-sm text-gray-900 border border-gray-300 rounded-md cursor-pointer bg-gray-50 focus:outline-none focus:ring-blue-500 focus:border-blue-500 file:mr-4 file:py-2 file:px-4 file:rounded-l-md file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100">
                </div>
                <div class="mt-4">
                    <label for="key_passphrase" class="block text-sm font-medium text-gray-700">Mật khẩu khóa (Key Passphrase, nếu có):</label>
                    <input type="password" name="key_passphrase" id="key_passphrase"
                           class="mt-1 block w-full px-3 py-2 bg-white border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                           placeholder="Để trống nếu khóa không có mật khẩu">
                </div>
            </div>

            <div class="border-t border-gray-200 pt-6 mt-6">
                <h2 class="text-lg font-medium text-gray-900 mb-1">Hoặc Xác thực bằng Mật khẩu</h2>
                 <p class="text-xs text-gray-500 mb-3">Sử dụng nếu không cung cấp tệp khóa. Chỉ cần cung cấp một lần cho mỗi phiên kết nối.</p>
                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700">Mật khẩu đăng nhập:</label>
                    <input type="password" name="password" id="password"
                           class="mt-1 block w-full px-3 py-2 bg-white border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                </div>
            </div>
            
            <div class="mt-6">
                <label for="command" class="block text-sm font-medium text-gray-700">Lệnh thực thi:</label>
                <textarea name="command" id="command" rows="3" required
                          class="mt-1 block w-full px-3 py-2 bg-white border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">{% if session.get('command') %}{{ session.get('command') }}{% else %}ls -lha{% endif %}</textarea>
            </div>

            <div>
                <button type="submit"
                        class="w-full flex justify-center py-3 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition duration-150 ease-in-out">
                    Thực thi lệnh
                </button>
            </div>
        </form>

        <!-- Hiển thị Output được tích lũy -->
        {% if session.get('output') %}
            <div class="mt-8">
                <h2 class="text-xl font-semibold text-gray-800 mb-3">Lịch sử Output:</h2>
                <pre class="bg-gray-900 text-white text-sm p-4 rounded-md shadow-inner overflow-auto max-h-[500px]">{{ session.get('output') }}</pre>
            </div>
        {% endif %}
        
        <!-- Hiển thị lỗi SSH tức thời (không tích lũy vào output chính) -->
        {% if ssh_error_once %}
            <div class="mt-8">
                <h2 class="text-xl font-semibold text-red-600 mb-3">Lỗi SSH (Lần này):</h2>
                <pre class="bg-red-50 text-red-700 text-sm p-4 rounded-md shadow-inner overflow-x-auto max-h-96">{{ ssh_error_once }}</pre>
            </div>
        {% endif %}
        
        <footer class="mt-8 text-center text-sm text-gray-500">
            <p>SSH Web Client đơn giản. Sử dụng cẩn thận.</p>
            <p>Phát triển với Flask & Paramiko.</p>
        </footer>
    </div>
</body>
</html>
"""

def get_client_session_id():
    """Lấy hoặc tạo client_session_id duy nhất cho session."""
    if 'client_session_id' not in session:
        session['client_session_id'] = os.urandom(16).hex()
    return session['client_session_id']

@app.route('/', methods=['GET'])
def index():
    get_client_session_id() # Đảm bảo client_session_id tồn tại
    # Lấy lỗi SSH tức thời để hiển thị riêng, sau đó xóa khỏi session
    ssh_error_once = session.pop('ssh_error_once', None) 
    error = session.pop('error', None) 
    message = session.pop('message', None)
    # session['output'] sẽ được truy cập trực tiếp trong template để hiển thị lịch sử
    return render_template_string(INDEX_HTML, ssh_error_once=ssh_error_once, error=error, message=message, session=session)

@app.route('/disconnect', methods=['GET'])
def disconnect_ssh():
    client_id = get_client_session_id()
    client = active_ssh_clients.pop(client_id, None)
    if client:
        try:
            client.close()
            logger.info(f"Đã đóng kết nối SSH cho client ID: {client_id}")
        except Exception as e:
            logger.error(f"Lỗi khi đóng kết nối SSH cho client ID {client_id}: {e}")
    
    session.pop('active_connection_target', None)
    session.pop('loaded_pkey_for_session', None) 
    session.pop('output', None) # Xóa toàn bộ lịch sử output
    session['message'] = "Đã ngắt kết nối SSH và xóa lịch sử output."
    return redirect(url_for('index'))

@app.route('/execute', methods=['POST'])
def handle_ssh_command():
    client_id = get_client_session_id()

    host = request.form.get('host')
    port_str = request.form.get('port', '22')
    username = request.form.get('username')
    command = request.form.get('command')
    
    password_from_form = request.form.get('password')
    private_key_file_storage = request.files.get('private_key_file')
    key_passphrase_from_form = request.form.get('key_passphrase')

    session['host'] = host
    session['username'] = username
    session['command'] = command # Lưu lệnh hiện tại để điền lại form
    
    try:
        port = int(port_str)
        if port <= 0 or port > 65535:
            raise ValueError("Số cổng không hợp lệ.")
        session['port'] = port
    except ValueError:
        session['error'] = f"Số cổng '{port_str}' không hợp lệ."
        return redirect(url_for('index'))

    if not all([host, username, command]):
        session['error'] = "Vui lòng điền đầy đủ: Máy chủ, Tên đăng nhập và Lệnh."
        return redirect(url_for('index'))

    current_target_str = f"{username}@{host}:{port}"
    ssh_client = active_ssh_clients.get(client_id)
    
    is_client_valid_for_target = False
    if ssh_client:
        transport = ssh_client.get_transport()
        if transport and transport.is_active():
            if session.get('active_connection_target') == current_target_str:
                is_client_valid_for_target = True
            else: 
                logger.info(f"Target SSH đã thay đổi cho client ID {client_id}. Đóng kết nối cũ.")
                ssh_client.close()
                active_ssh_clients.pop(client_id, None)
                session.pop('active_connection_target', None)
                session.pop('loaded_pkey_for_session', None)
                session['output'] = "" # Xóa output cho target mới
                ssh_client = None
        else: 
            logger.info(f"Client SSH không còn hoạt động cho client ID {client_id}. Xóa bỏ.")
            active_ssh_clients.pop(client_id, None)
            session.pop('active_connection_target', None)
            session.pop('loaded_pkey_for_session', None)
            session['output'] = "" # Xóa output nếu client chết
            ssh_client = None

    if not is_client_valid_for_target:
        logger.info(f"Không có client SSH hợp lệ cho {current_target_str}. Thử kết nối mới.")
        session['output'] = "" # Đảm bảo output trống cho kết nối mới/target mới
        
        loaded_pkey = None
        if private_key_file_storage and private_key_file_storage.filename != '':
            try:
                private_key_data = private_key_file_storage.read().decode('utf-8')
                key_file_obj = io.StringIO(private_key_data)
                actual_key_passphrase = key_passphrase_from_form if key_passphrase_from_form else None
                
                key_types_to_try = [RSAKey, DSSKey, ECDSAKey, Ed25519Key]
                for key_type_class in key_types_to_try:
                    try:
                        key_file_obj.seek(0)
                        loaded_pkey = key_type_class.from_private_key(key_file_obj, password=actual_key_passphrase)
                        logger.info(f"Đã tải thành công khóa riêng tư dạng {key_type_class.__name__}.")
                        break 
                    except (paramiko.SSHException, TypeError, ValueError) : 
                        logger.debug(f"Không thể tải khóa dạng {key_type_class.__name__}.")
                        continue
                if not loaded_pkey:
                    session['ssh_error_once'] = "Không thể tải khóa riêng tư. Định dạng, mật khẩu khóa sai hoặc loại khóa không hỗ trợ."
                    return redirect(url_for('index'))
            except Exception as e:
                session['ssh_error_once'] = f"Lỗi khi xử lý tệp khóa: {str(e)}"
                return redirect(url_for('index'))

        if not loaded_pkey and not password_from_form:
            session['error'] = "Vui lòng cung cấp Mật khẩu hoặc Tệp Khóa Riêng Tư."
            return redirect(url_for('index'))

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                'hostname': host, 'port': port, 'username': username,
                'timeout': 10, 'allow_agent': False, 'look_for_keys': False
            }
            auth_method_log = ""
            if loaded_pkey:
                connect_kwargs['pkey'] = loaded_pkey
                auth_method_log = "sử dụng khóa riêng tư"
            elif password_from_form:
                connect_kwargs['password'] = password_from_form
                auth_method_log = "sử dụng mật khẩu"
            
            logger.info(f"Đang thử kết nối SSH mới tới {current_target_str} {auth_method_log}.")
            ssh_client.connect(**connect_kwargs)
            
            active_ssh_clients[client_id] = ssh_client
            session['active_connection_target'] = current_target_str
            logger.info(f"Kết nối SSH mới thành công tới {current_target_str} cho client ID {client_id}.")
            session['message'] = f"Đã kết nối tới {current_target_str}." # Thông báo kết nối thành công

        except paramiko.AuthenticationException:
            session['ssh_error_once'] = "Lỗi xác thực. Kiểm tra lại thông tin đăng nhập/khóa."
            return redirect(url_for('index'))
        except (socket.timeout, paramiko.SSHException, TimeoutError) as e: # TimeoutError từ exec_command cũng có thể là SSHException
            session['ssh_error_once'] = f"Lỗi kết nối SSH: {str(e)}"
            return redirect(url_for('index'))
        except Exception as e:
            session['ssh_error_once'] = f"Lỗi không mong muốn khi kết nối: {str(e)}"
            return redirect(url_for('index'))

    if not ssh_client:
        session['ssh_error_once'] = "Không thể thiết lập hoặc sử dụng lại kết nối SSH."
        return redirect(url_for('index'))
        
    try:
        logger.info(f"Client ID {client_id} thực thi lệnh: '{command}' trên {session.get('active_connection_target')}")
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=20)
        output_data = stdout.read().decode('utf-8', errors='replace') # Giữ nguyên newlines từ server
        error_data = stderr.read().decode('utf-8', errors='replace')   # Giữ nguyên newlines từ server

        # Lấy output hiện tại từ session
        previous_session_output = session.get('output', "")
        
        # Dòng lệnh đã thực thi (prompt)
        prompt_line = f"{session.get('active_connection_target', 'local')}> {command}\n"
        
        # Kết quả lệnh
        command_result_text = ""
        if output_data:
            command_result_text += output_data # Đã có newline từ server
        if error_data:
            command_result_text += error_data # Đã có newline từ server
        
        if not output_data and not error_data:
            # Thêm một newline nếu không có output gì để đảm bảo định dạng
            command_result_text = "[Không có kết quả đầu ra hoặc lỗi từ lệnh]\n" 

        # Nối vào output cũ, thêm một dòng trống giữa các khối lệnh nếu đã có output cũ
        separator = "\n" if previous_session_output.strip() else ""
        session['output'] = previous_session_output + separator + prompt_line + command_result_text

    except Exception as e:
        # Lỗi này xảy ra trong quá trình thực thi lệnh, không phải lỗi kết nối ban đầu
        # Chúng ta nên hiển thị nó như một phần của output lệnh đó
        error_message = f"Lỗi khi thực thi lệnh '{command}': {str(e)}\n"
        prompt_line = f"{session.get('active_connection_target', 'local')}> {command}\n"
        previous_session_output = session.get('output', "")
        separator = "\n" if previous_session_output.strip() else ""
        session['output'] = previous_session_output + separator + prompt_line + error_message
        
        # Vì lỗi có thể làm hỏng client, đóng và xóa nó
        client = active_ssh_clients.pop(client_id, None)
        if client: client.close()
        session.pop('active_connection_target', None)
        # Giữ lại 'output' đã được cập nhật với lỗi này
        session['ssh_error_once'] = f"Lỗi khi thực thi lệnh. Kết nối có thể đã bị đóng."


    return redirect(url_for('index'))

if __name__ == '__main__':
    print("SSH Web Client đang chạy tại http://127.0.0.1:5001")
    print("Để truy cập từ máy khác trong cùng mạng, sử dụng http://<địa-chỉ-ip-máy-chạy-app>:5001")
    app.run(debug=True, host='0.0.0.0', port=5001)
