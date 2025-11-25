"""
Bot de WhatsApp con Control desde Signal
Requiere: pip install anthropic schedule pytz pydub SpeechRecognition pysignalcli
"""

import os
import json
import schedule
import time
import re
from datetime import datetime
from typing import List, Dict, Tuple
import anthropic
from whatsapp_web import WhatsAppWeb
import imaplib
import email
from email.header import decode_header
import speech_recognition as sr
from pydub import AudioSegment
import subprocess
import signal as signal_module

# ==================== CONFIGURACIÓN ====================
class Config:
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")
    
    # Números de teléfono
    YOUR_PHONE = "+"  # Tu número personal (formato internacional)
    
    # Signal CLI path (ajustar según instalación)
    SIGNAL_CLI_PATH = "signal-cli"
    
    # Configuración de email
    EMAIL_ADDRESS = "tu-email@gmail.com"
    EMAIL_PASSWORD = "tu-password-de-app"
    IMAP_SERVER = "imap.gmail.com"
    
    # Horarios para resúmenes
    SUMMARY_TIMES = ["09:00", "18:00"]
    
    # Palabras clave para urgencia
    URGENT_KEYWORDS = ["urgente", "emergencia", "importante", "asap", "ya", "ahora"]
    
    # Detección de seguridad y códigos
    SECURITY_KEYWORDS = [
        "código", "codigo", "verificación", "verificacion", "OTP", "2FA",
        "contraseña", "password", "clave", "token", "PIN", "acceso",
        "seguridad", "autenticación", "autenticacion", "login",
        "suspicious", "sospechoso", "alerta", "intento de acceso",
        "dispositivo nuevo", "nueva ubicación", "ubicacion desconocida",
        "bloqueo", "bloqueado", "desactivado", "suspendido"
    ]
    
    # Remitentes de seguridad conocidos
    SECURITY_SENDERS = [
        "noreply", "no-reply", "security", "seguridad", 
        "alert", "notification", "verify", "auth",
        "google", "microsoft", "apple", "facebook", "instagram",
        "twitter", "bank", "banco", "paypal", "stripe",
        "aws", "cloudflare", "github", "gitlab"
    ]
    
    # Patrones de códigos (se detectan con regex)
    # Ejemplos: 123456, ABC-123, G-123456, etc.
    
    # Filtros adicionales
    IGNORE_GROUPS = True  # Ignorar todos los grupos
    IGNORE_MUTED = True   # Ignorar contactos silenciados
    
    # Lista de contactos/grupos específicos a ignorar (números o nombres)
    BLACKLIST = [
        # Ejemplos:
        # "+34666777888",
        # "Nombre del Grupo",
        # "Contacto Spam"
    ]
    
    # Lista blanca (solo responder a estos contactos, dejar vacío para todos)
    WHITELIST = [
        # Si está vacío, responde a todos (excepto filtros anteriores)
        # Si tiene contactos, SOLO responde a estos
    ]

# ==================== CLIENTE DE SIGNAL ====================
class SignalClient:
    """Cliente para enviar y recibir mensajes de Signal"""
    
    def __init__(self):
        self.phone = Config.YOUR_PHONE
        self.cli_path = Config.SIGNAL_CLI_PATH
    
    def send_message(self, message: str, recipient: str = None):
        """Envía mensaje por Signal"""
        if recipient is None:
            recipient = self.phone
        
        try:
            cmd = [
                self.cli_path,
                "-a", self.phone,
                "send",
                "-m", message,
                recipient
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"✓ Mensaje enviado por Signal")
            return True
        except Exception as e:
            print(f"Error enviando mensaje Signal: {e}")
            return False
    
    def receive_messages(self):
        """Recibe mensajes nuevos de Signal"""
        try:
            cmd = [
                self.cli_path,
                "-a", self.phone,
                "receive",
                "--json"
            ]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            messages = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        msg_data = json.loads(line)
                        if msg_data.get('envelope', {}).get('dataMessage'):
                            messages.append(msg_data)
                    except json.JSONDecodeError:
                        continue
            
            return messages
        except Exception as e:
            print(f"Error recibiendo mensajes Signal: {e}")
            return []
    
    def send_with_attachment(self, message: str, file_path: str):
        """Envía mensaje con archivo adjunto"""
        try:
            cmd = [
                self.cli_path,
                "-a", self.phone,
                "send",
                "-m", message,
                "-a", file_path,
                self.phone
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except Exception as e:
            print(f"Error enviando adjunto Signal: {e}")
            return False

# ==================== DETECTOR DE SEGURIDAD ====================
class SecurityDetector:
    """Detecta alertas de seguridad, códigos OTP y avisos importantes"""
    
    # Patrones regex para detectar códigos
    CODE_PATTERNS = [
        r'\b\d{4,8}\b',  # Códigos numéricos de 4-8 dígitos
        r'\b[A-Z0-9]{6}\b',  # Códigos alfanuméricos de 6 caracteres
        r'\b[A-Z]-\d{6}\b',  # Formato G-123456
        r'\b\d{3}-\d{3}\b',  # Formato 123-456
        r'\bOTP[:\s]+(\d{4,6})\b',  # OTP: 123456
        r'\bcódigo[:\s]+(\d{4,8})\b',  # código: 123456
        r'\bcode[:\s]+([A-Z0-9]{4,8})\b',  # code: ABC123
    ]
    
    @staticmethod
    def analyze_message(text: str, sender: str) -> Dict:
        """
        Analiza un mensaje y determina si contiene alertas de seguridad
        
        Returns:
            {
                'is_security_alert': bool,
                'alert_type': str,  # 'code', 'login_alert', 'suspicious_activity', etc.
                'codes_found': List[str],
                'confidence': int,  # 0-100
                'reason': str
            }
        """
        text_lower = text.lower()
        sender_lower = sender.lower()
        
        result = {
            'is_security_alert': False,
            'alert_type': None,
            'codes_found': [],
            'confidence': 0,
            'reason': ''
        }
        
        confidence = 0
        reasons = []
        
        # 1. Detectar códigos de verificación
        codes = SecurityDetector.extract_codes(text)
        if codes:
            result['codes_found'] = codes
            confidence += 40
            reasons.append(f"Códigos detectados: {', '.join(codes)}")
        
        # 2. Verificar palabras clave de seguridad
        security_keywords_found = [kw for kw in Config.SECURITY_KEYWORDS if kw in text_lower]
        if security_keywords_found:
            confidence += len(security_keywords_found) * 5
            reasons.append(f"Palabras clave: {', '.join(security_keywords_found[:3])}")
        
        # 3. Verificar remitente conocido de seguridad
        is_security_sender = any(sender_pattern in sender_lower for sender_pattern in Config.SECURITY_SENDERS)
        if is_security_sender:
            confidence += 30
            reasons.append("Remitente de seguridad conocido")
        
        # 4. Detectar patrones específicos
        if any(pattern in text_lower for pattern in ['inicio de sesión', 'login attempt', 'new device', 'nuevo dispositivo']):
            result['alert_type'] = 'login_alert'
            confidence += 20
            reasons.append("Alerta de inicio de sesión")
        
        if any(pattern in text_lower for pattern in ['actividad sospechosa', 'suspicious activity', 'fraude', 'fraud']):
            result['alert_type'] = 'suspicious_activity'
            confidence += 30
            reasons.append("Actividad sospechosa detectada")
        
        if any(pattern in text_lower for pattern in ['cuenta bloqueada', 'account locked', 'suspendido', 'suspended']):
            result['alert_type'] = 'account_locked'
            confidence += 25
            reasons.append("Alerta de cuenta bloqueada")
        
        if codes and any(kw in text_lower for kw in ['verificación', 'verification', 'otp', '2fa']):
            result['alert_type'] = 'verification_code'
            confidence += 35
            reasons.append("Código de verificación")
        
        # Determinar si es alerta de seguridad
        result['confidence'] = min(confidence, 100)
        result['is_security_alert'] = confidence >= 30
        result['reason'] = ' | '.join(reasons)
        
        return result
    
    @staticmethod
    def extract_codes(text: str) -> List[str]:
        """Extrae códigos del texto usando patrones regex"""
        codes = []
        
        for pattern in SecurityDetector.CODE_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                code = match.group(0)
                # Filtrar falsos positivos (años, números comunes, etc.)
                if SecurityDetector.is_valid_code(code):
                    codes.append(code)
        
        return list(set(codes))  # Eliminar duplicados
    
    @staticmethod
    def is_valid_code(code: str) -> bool:
        """Valida que un código no sea un falso positivo"""
        # Evitar años
        if code.isdigit() and 1900 <= int(code) <= 2100:
            return False
        
        # Evitar números muy comunes
        common_numbers = ['0000', '1111', '2222', '1234', '12345']
        if code in common_numbers:
            return False
        
        return True
    
    @staticmethod
    def format_security_alert(analysis: Dict, message_data: Dict) -> str:
        """Formatea una alerta de seguridad para notificación"""
        alert_icons = {
            'verification_code': '🔐',
            'login_alert': '🚪',
            'suspicious_activity': '⚠️',
            'account_locked': '🔒',
            None: '🔔'
        }
        
        icon = alert_icons.get(analysis['alert_type'], '🔔')
        alert_type = analysis['alert_type'] or 'security_alert'
        
        notification = f"""{icon} ALERTA DE SEGURIDAD ({analysis['confidence']}% confianza)

Tipo: {alert_type.replace('_', ' ').title()}
De: {message_data.get('sender_name', 'Desconocido')}
Origen: {message_data.get('source', 'WhatsApp')}

"""
        
        if analysis['codes_found']:
            notification += f"🔢 CÓDIGOS DETECTADOS:\n"
            for code in analysis['codes_found']:
                notification += f"   → {code}\n"
            notification += "\n"
        
        notification += f"📝 Mensaje:\n{message_data.get('text', '')[:300]}\n"
        
        if analysis['reason']:
            notification += f"\n💡 Detección: {analysis['reason']}"
        
        return notification
class MessageManager:
    def __init__(self):
        self.messages = []
        self.load_messages()
    
    def add_message(self, msg: Dict):
        """Añade un mensaje y lo prioriza"""
        msg['timestamp'] = datetime.now().isoformat()
        msg['priority'] = self.calculate_priority(msg)
        self.messages.append(msg)
        self.messages.sort(key=lambda x: x['priority'], reverse=True)
        self.save_messages()
    
    def calculate_priority(self, msg: Dict) -> int:
        """Calcula prioridad del mensaje (0-10)"""
        priority = 5  # Base
        
        text = msg.get('text', '').lower()
        
        # Detectar urgencia
        if any(keyword in text for keyword in Config.URGENT_KEYWORDS):
            priority += 3
            msg['is_urgent'] = True
        
        # Preguntas directas
        if '?' in text:
            priority += 1
        
        # Longitud del mensaje
        if len(text) > 200:
            priority += 1
        
        return min(priority, 10)
    
    def get_urgent_messages(self) -> List[Dict]:
        """Obtiene mensajes urgentes no procesados"""
        return [msg for msg in self.messages 
                if msg.get('is_urgent') and not msg.get('notified')]
    
    def mark_notified(self, msg_id: str):
        """Marca mensaje como notificado"""
        for msg in self.messages:
            if msg.get('id') == msg_id:
                msg['notified'] = True
                break
        self.save_messages()
    
    def get_summary_data(self, hours: int = None) -> List[Dict]:
        """Obtiene mensajes para resumen"""
        messages = [msg for msg in self.messages if not msg.get('summarized')]
        
        # Filtrar por tiempo si se especifica
        if hours:
            cutoff = datetime.now().timestamp() - (hours * 3600)
            messages = [msg for msg in messages 
                       if datetime.fromisoformat(msg['timestamp']).timestamp() > cutoff]
        
        return messages
    
    def mark_summarized(self):
        """Marca mensajes como resumidos"""
        for msg in self.messages:
            msg['summarized'] = True
        self.save_messages()
    
    def get_message_by_sender(self, sender_name: str) -> List[Dict]:
        """Busca mensajes por remitente"""
        return [msg for msg in self.messages 
                if sender_name.lower() in msg.get('sender', '').lower()]
    
    def save_messages(self):
        """Guarda mensajes en archivo"""
        with open('messages_db.json', 'w') as f:
            json.dump(self.messages, f, indent=2)
    
    def load_messages(self):
        """Carga mensajes desde archivo"""
        try:
            with open('messages_db.json', 'r') as f:
                self.messages = json.load(f)
        except FileNotFoundError:
            self.messages = []
    
    def get_stats(self) -> Dict:
        """Obtiene estadísticas de mensajes"""
        total = len(self.messages)
        urgent = len([m for m in self.messages if m.get('is_urgent')])
        pending = len([m for m in self.messages if not m.get('summarized')])
        
        return {
            'total': total,
            'urgent': urgent,
            'pending': pending
        }

# ==================== CLIENTE DE CLAUDE ====================
class ClaudeAssistant:
    def __init__(self):
        self.client = anthropic.Anthropic(api_key=Config.ANTHROPIC_API_KEY)
    
    def process_message(self, msg_text: str, sender: str) -> str:
        """Procesa un mensaje y genera respuesta"""
        prompt = f"""Eres un asistente personal. Recibiste este mensaje de WhatsApp de {sender}:

"{msg_text}"

Genera una respuesta profesional, amigable y útil. Si es necesario, puedes:
- Confirmar que recibiste el mensaje
- Proporcionar información relevante
- Hacer preguntas de seguimiento
- Sugerir acciones

Responde de forma concisa (máximo 3 párrafos)."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response.content[0].text
    
    def process_signal_command(self, command_text: str) -> Dict:
        """Procesa comando recibido desde Signal"""
        prompt = f"""Eres un asistente que procesa comandos. El usuario te escribió desde Signal:

"{command_text}"

Determina qué acción quiere realizar. Responde SOLO con un JSON con esta estructura:
{{
    "action": "summary|reply|search|stats|filters|blacklist|whitelist|remove_filter|help|custom",
    "parameters": {{
        "target": "destinatario o filtro",
        "message": "mensaje a enviar si aplica",
        "filter": "filtro de búsqueda si aplica",
        "hours": "número de horas para resumen si aplica"
    }},
    "response": "respuesta amigable confirmando la acción"
}}

Acciones disponibles:
- "resumen" o "summary" -> acción: summary
- "responde a X que..." -> acción: reply
- "buscar mensajes de X" -> acción: search
- "estadísticas" o "stats" -> acción: stats
- "filtros" -> acción: filters
- "bloquear X" o "ignorar X" -> acción: blacklist
- "solo responder X" o "whitelist X" -> acción: whitelist
- "desbloquear X" o "quitar filtro X" -> acción: remove_filter
- "ayuda" -> acción: help"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=250,
            messages=[{"role": "user", "content": prompt}]
        )
        
        try:
            return json.loads(response.content[0].text)
        except:
            return {
                "action": "help",
                "response": "No entendí el comando. Escribe 'ayuda' para ver comandos disponibles."
            }
    
    def process_voice_command(self, transcription: str) -> Dict:
        """Procesa comando de voz para gestionar mensajes"""
        prompt = f"""Eres un asistente que procesa comandos de voz. El usuario dijo:

"{transcription}"

Determina qué acción quiere realizar con sus mensajes de WhatsApp. Responde SOLO con un JSON:
{{
    "action": "reply|archive|prioritize|schedule|info",
    "target": "nombre o descripción del mensaje objetivo",
    "parameters": {{"message": "texto de respuesta si action=reply"}},
    "confirmation": "mensaje de confirmación para el usuario"
}}"""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}]
        )
        
        try:
            return json.loads(response.content[0].text)
        except:
            return {"action": "error", "confirmation": "No pude procesar el comando"}
    
    def generate_summary(self, messages: List[Dict], emails: List[Dict]) -> str:
        """Genera resumen de mensajes y emails"""
        msg_text = "\n".join([f"- [{m['priority']}] {m['sender']}: {m['text'][:100]}..." 
                              for m in messages[:15]])
        email_text = "\n".join([f"- {e['from']}: {e['subject']}" 
                                for e in emails[:5]])
        
        prompt = f"""Genera un resumen ejecutivo conciso de estos mensajes y emails:

MENSAJES WHATSAPP ({len(messages)} total):
{msg_text if msg_text else 'Ninguno'}

EMAILS ({len(emails)} total):
{email_text if email_text else 'Ninguno'}

Proporciona:
1. Resumen de cantidad y urgencias
2. Top 3 mensajes más importantes
3. Acciones recomendadas urgentes
4. Cualquier seguimiento necesario

Formato claro con emojis. Máximo 250 palabras."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response.content[0].text

# ==================== GESTOR DE EMAIL ====================
class EmailManager:
    def __init__(self):
        self.imap = None
    
    def connect(self):
        """Conecta al servidor IMAP"""
        try:
            self.imap = imaplib.IMAP4_SSL(Config.IMAP_SERVER)
            self.imap.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
            return True
        except Exception as e:
            print(f"Error conectando email: {e}")
            return False
    
    def get_unread_emails(self) -> List[Dict]:
        """Obtiene emails no leídos"""
        if not self.imap:
            if not self.connect():
                return []
        
        try:
            self.imap.select("INBOX")
            _, messages = self.imap.search(None, "UNSEEN")
            
            emails = []
            security_detector = SecurityDetector()
            
            for msg_num in messages[0].split()[-10:]:  # Últimos 10
                _, msg_data = self.imap.fetch(msg_num, "(RFC822)")
                email_body = msg_data[0][1]
                message = email.message_from_bytes(email_body)
                
                subject = decode_header(message["Subject"])[0][0]
                if isinstance(subject, bytes):
                    subject = subject.decode()
                
                sender = message["From"]
                
                # Obtener cuerpo del email
                body = ""
                if message.is_multipart():
                    for part in message.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            break
                else:
                    body = message.get_payload(decode=True).decode('utf-8', errors='ignore')
                
                # Combinar subject y body para análisis
                full_text = f"{subject}\n{body}"
                
                # Detectar seguridad
                security_analysis = security_detector.analyze_message(full_text, sender)
                
                email_data = {
                    "from": sender,
                    "subject": subject,
                    "date": message["Date"],
                    "body": body[:500],  # Primeros 500 caracteres
                    "is_security_alert": security_analysis['is_security_alert'],
                    "security_analysis": security_analysis if security_analysis['is_security_alert'] else None
                }
                
                emails.append(email_data)
            
            return emails
        except Exception as e:
            print(f"Error obteniendo emails: {e}")
            return []
    
    def disconnect(self):
        """Cierra conexión"""
        if self.imap:
            self.imap.close()
            self.imap.logout()

# ==================== PROCESADOR DE AUDIO ====================
class AudioProcessor:
    def __init__(self):
        self.recognizer = sr.Recognizer()
    
    def transcribe_audio(self, audio_path: str) -> str:
        """Transcribe audio de WhatsApp a texto"""
        try:
            # Convertir audio de WhatsApp (opus/ogg) a WAV
            audio = AudioSegment.from_file(audio_path)
            wav_path = audio_path.replace('.ogg', '.wav').replace('.opus', '.wav')
            audio.export(wav_path, format='wav')
            
            # Transcribir
            with sr.AudioFile(wav_path) as source:
                audio_data = self.recognizer.record(source)
                text = self.recognizer.recognize_google(audio_data, language='es-ES')
            
            # Limpiar archivo temporal
            os.remove(wav_path)
            
            return text
        except Exception as e:
            print(f"Error transcribiendo audio: {e}")
            return ""

# ==================== BOT PRINCIPAL ====================
class WhatsAppSignalAssistant:
    def __init__(self):
        self.wa = WhatsAppWeb()
        self.signal = SignalClient()
        self.msg_manager = MessageManager()
        self.claude = ClaudeAssistant()
        self.email_manager = EmailManager()
        self.audio_processor = AudioProcessor()
        self.running = True
        
        # Cargar configuración de filtros guardada
        self.load_config()
        
    def start(self):
        """Inicia el bot"""
        print("=" * 50)
        print("🤖 INICIANDO BOT DE WHATSAPP + SIGNAL")
        print("=" * 50)
        
        # Conectar a WhatsApp
        print("\n📱 Conectando a WhatsApp...")
        self.wa.connect()
        print("✓ WhatsApp conectado")
        
        # Configurar manejador de mensajes de WhatsApp
        self.wa.on_message(self.handle_whatsapp_message)
        
        # Programar resúmenes automáticos
        for time_str in Config.SUMMARY_TIMES:
            schedule.every().day.at(time_str).do(self.send_scheduled_summary)
        
        # Enviar mensaje de inicio por Signal
        self.signal.send_message(
            "🤖 Bot iniciado correctamente\n\n"
            "Estoy monitoreando tus mensajes de WhatsApp.\n"
            "Comandos disponibles:\n"
            "• 'resumen' - Resumen inmediato\n"
            "• 'stats' - Estadísticas\n"
            "• 'responde a [nombre] que [mensaje]'\n"
            "• 'ayuda' - Ver todos los comandos"
        )
        
        print("\n✓ Bot iniciado correctamente")
        print("📡 Monitoreando WhatsApp y Signal...\n")
        
        # Loop principal
        try:
            while self.running:
                # Procesar comandos de Signal
                self.check_signal_commands()
                
                # Verificar emails con alertas de seguridad cada 2 minutos
                if int(time.time()) % 120 == 0:
                    self.check_and_notify_email_security()
                
                # Ejecutar tareas programadas
                schedule.run_pending()
                
                time.sleep(2)  # Check cada 2 segundos
        except KeyboardInterrupt:
            print("\n\n🛑 Deteniendo bot...")
            self.stop()
    
    def handle_whatsapp_message(self, message):
        """Maneja mensajes entrantes de WhatsApp"""
        # Ignorar mensajes propios
        if message.sender == Config.YOUR_PHONE:
            return
        
        # Aplicar filtros
        if not self.should_process_message(message):
            return
        
        msg_data = {
            'id': message.id,
            'sender': message.sender,
            'sender_name': message.sender_name or message.sender,
            'text': message.text or '',
            'type': message.type,
            'is_group': message.is_group,
            'is_muted': message.chat.is_muted if hasattr(message, 'chat') else False,
            'source': 'WhatsApp'
        }
        
        print(f"📩 Nuevo mensaje WA de {msg_data['sender_name']}")
        
        # Procesar audio si es nota de voz
        if message.type == 'audio':
            audio_path = message.download_media()
            transcription = self.audio_processor.transcribe_audio(audio_path)
            
            if transcription:
                msg_data['text'] = f"[Audio transcrito]: {transcription}"
        
        # Añadir mensaje a la base de datos (esto detecta seguridad automáticamente)
        self.msg_manager.add_message(msg_data)
        
        # Verificar si es alerta de seguridad y notificar por Signal
        if msg_data.get('is_security_alert'):
            self.notify_security_alert(msg_data)
        # Si no es de seguridad pero es urgente, notificar como urgente
        elif msg_data.get('is_urgent'):
            self.notify_urgent_message(msg_data)
        
        # Generar respuesta automática en WhatsApp
        response = self.claude.process_message(msg_data['text'], msg_data['sender_name'])
        self.wa.send_message(message.sender, response)
        print(f"✓ Respuesta enviada a {msg_data['sender_name']}")
    
    def should_process_message(self, message) -> bool:
        """Determina si un mensaje debe ser procesado según los filtros"""
        sender_name = message.sender_name or message.sender
        
        # 1. Verificar si es grupo y están deshabilitados
        if Config.IGNORE_GROUPS and message.is_group:
            print(f"⊘ Ignorando mensaje de grupo: {message.chat_name}")
            return False
        
        # 2. Verificar si el contacto está silenciado
        if Config.IGNORE_MUTED and hasattr(message, 'chat') and message.chat.is_muted:
            print(f"🔇 Ignorando contacto silenciado: {sender_name}")
            return False
        
        # 3. Verificar blacklist (lista negra)
        if Config.BLACKLIST:
            for blocked in Config.BLACKLIST:
                if blocked in message.sender or blocked in sender_name:
                    print(f"🚫 Contacto en blacklist: {sender_name}")
                    return False
        
        # 4. Verificar whitelist (lista blanca) - si existe, solo procesar estos
        if Config.WHITELIST:
            is_whitelisted = False
            for allowed in Config.WHITELIST:
                if allowed in message.sender or allowed in sender_name:
                    is_whitelisted = True
                    break
            
            if not is_whitelisted:
                print(f"⚪ Contacto no está en whitelist: {sender_name}")
                return False
        
        # Si pasó todos los filtros
        return True
    
    def check_signal_commands(self):
        """Verifica comandos desde Signal"""
        messages = self.signal.receive_messages()
        
        for msg in messages:
            try:
                envelope = msg.get('envelope', {})
                data_msg = envelope.get('dataMessage', {})
                text = data_msg.get('message', '').strip()
                
                if not text:
                    continue
                
                print(f"📲 Comando Signal: {text}")
                
                # Procesar comando
                command = self.claude.process_signal_command(text)
                self.execute_signal_command(command)
                
            except Exception as e:
                print(f"Error procesando comando Signal: {e}")
    
    def execute_signal_command(self, command: Dict):
        """Ejecuta comando recibido desde Signal"""
        action = command.get('action')
        params = command.get('parameters', {})
        
        if action == 'summary':
            # Generar resumen inmediato
            hours = params.get('hours')
            self.send_summary(hours=int(hours) if hours else None)
        
        elif action == 'reply':
            # Responder mensaje de WhatsApp
            target = params.get('target')
            message = params.get('message')
            self.reply_to_whatsapp(target, message)
        
        elif action == 'search':
            # Buscar mensajes
            filter_text = params.get('filter')
            results = self.search_messages(filter_text)
            self.signal.send_message(results)
        
        elif action == 'stats':
            # Enviar estadísticas
            stats = self.msg_manager.get_stats()
            stats_text = f"""📊 ESTADÍSTICAS

Total mensajes: {stats['total']}
Urgentes: {stats['urgent']} 🚨
Pendientes: {stats['pending']}

Filtros activos:
• Ignorar grupos: {'✓' if Config.IGNORE_GROUPS else '✗'}
• Ignorar silenciados: {'✓' if Config.IGNORE_MUTED else '✗'}
• Blacklist: {len(Config.BLACKLIST)} contactos
• Whitelist: {len(Config.WHITELIST) if Config.WHITELIST else 'Desactivada'}"""
            self.signal.send_message(stats_text)
        
        elif action == 'filters':
            # Mostrar filtros activos
            self.show_filters()
        
        elif action == 'blacklist':
            # Agregar a blacklist
            contact = params.get('target')
            if contact:
                self.add_to_blacklist(contact)
        
        elif action == 'whitelist':
            # Agregar a whitelist
            contact = params.get('target')
            if contact:
                self.add_to_whitelist(contact)
        
        elif action == 'remove_filter':
            # Quitar de blacklist/whitelist
            contact = params.get('target')
            if contact:
                self.remove_from_filters(contact)
        
        elif action == 'help':
            # Enviar ayuda
            help_text = """🤖 COMANDOS DISPONIBLES

📋 Resúmenes:
• "resumen" - Resumen completo
• "resumen últimas 3 horas"

💬 Respuestas:
• "responde a [nombre] que [mensaje]"

🔍 Búsqueda:
• "buscar mensajes de [nombre]"

📊 Info:
• "stats" - Estadísticas
• "filtros" - Ver filtros activos

🚫 Filtros:
• "bloquear [nombre]" - Añadir a blacklist
• "solo responder [nombre]" - Añadir a whitelist
• "desbloquear [nombre]" - Quitar de filtros

❓ Ayuda:
• "ayuda" - Este mensaje"""
            self.signal.send_message(help_text)
        
        # Enviar confirmación
        response = command.get('response', 'Comando procesado')
        self.signal.send_message(f"✓ {response}")
    
    def show_filters(self):
        """Muestra los filtros activos"""
        filters_text = """🔍 FILTROS ACTIVOS

⚙️ Configuración:
• Ignorar grupos: """ + ('✓ Activado' if Config.IGNORE_GROUPS else '✗ Desactivado') + """
• Ignorar silenciados: """ + ('✓ Activado' if Config.IGNORE_MUTED else '✗ Desactivado')
        
        if Config.BLACKLIST:
            filters_text += "\n\n🚫 BLACKLIST (bloqueados):\n"
            for contact in Config.BLACKLIST:
                filters_text += f"• {contact}\n"
        else:
            filters_text += "\n\n🚫 Blacklist: Vacía"
        
        if Config.WHITELIST:
            filters_text += "\n\n⚪ WHITELIST (solo estos):\n"
            for contact in Config.WHITELIST:
                filters_text += f"• {contact}\n"
        else:
            filters_text += "\n\n⚪ Whitelist: Desactivada (responde a todos)"
        
        self.signal.send_message(filters_text)
    
    def add_to_blacklist(self, contact: str):
        """Añade contacto a blacklist"""
        if contact not in Config.BLACKLIST:
            Config.BLACKLIST.append(contact)
            self.save_config()
            self.signal.send_message(f"🚫 '{contact}' añadido a blacklist. No recibirá respuestas automáticas.")
        else:
            self.signal.send_message(f"⚠️ '{contact}' ya está en blacklist")
    
    def add_to_whitelist(self, contact: str):
        """Añade contacto a whitelist"""
        if contact not in Config.WHITELIST:
            Config.WHITELIST.append(contact)
            self.save_config()
            self.signal.send_message(f"⚪ '{contact}' añadido a whitelist. Solo responderás a contactos en whitelist.")
        else:
            self.signal.send_message(f"⚠️ '{contact}' ya está en whitelist")
    
    def remove_from_filters(self, contact: str):
        """Remueve contacto de blacklist y whitelist"""
        removed = False
        
        if contact in Config.BLACKLIST:
            Config.BLACKLIST.remove(contact)
            removed = True
        
        if contact in Config.WHITELIST:
            Config.WHITELIST.remove(contact)
            removed = True
        
        if removed:
            self.save_config()
            self.signal.send_message(f"✓ '{contact}' removido de los filtros")
        else:
            self.signal.send_message(f"⚠️ '{contact}' no estaba en ningún filtro")
    
    def save_config(self):
        """Guarda configuración de filtros"""
        config_data = {
            'blacklist': Config.BLACKLIST,
            'whitelist': Config.WHITELIST,
            'ignore_groups': Config.IGNORE_GROUPS,
            'ignore_muted': Config.IGNORE_MUTED
        }
        
        with open('config_filters.json', 'w') as f:
            json.dump(config_data, f, indent=2)
        
        print("💾 Configuración de filtros guardada")
    
    def load_config(self):
        """Carga configuración de filtros"""
        try:
            with open('config_filters.json', 'r') as f:
                config_data = json.load(f)
                Config.BLACKLIST = config_data.get('blacklist', [])
                Config.WHITELIST = config_data.get('whitelist', [])
                Config.IGNORE_GROUPS = config_data.get('ignore_groups', True)
                Config.IGNORE_MUTED = config_data.get('ignore_muted', True)
            print("✓ Configuración de filtros cargada")
        except FileNotFoundError:
            print("ℹ️ No hay configuración guardada, usando valores por defecto")
    
    def notify_urgent_message(self, msg: Dict):
        """Notifica mensaje urgente por Signal"""
        notification = f"""🚨 MENSAJE URGENTE

De: {msg['sender_name']}
Prioridad: {msg['priority']}/10

Mensaje:
{msg['text'][:300]}

⚡ Responde 'responde a {msg['sender_name'].split()[0]} que [tu mensaje]' para contestar"""
        
        self.signal.send_message(notification)
        self.msg_manager.mark_notified(msg['id'])
        print(f"⚠️  Urgencia notificada por Signal")
    
    def notify_security_alert(self, msg: Dict):
        """Notifica alerta de seguridad por Signal"""
        security_analysis = msg.get('security_analysis', {})
        
        # Formatear alerta
        notification = SecurityDetector.format_security_alert(security_analysis, msg)
        
        # Enviar notificación prioritaria
        self.signal.send_message(notification)
        
        # Marcar como notificado
        self.msg_manager.mark_notified(msg['id'])
        
        print(f"🔐 Alerta de seguridad notificada - Confianza: {security_analysis.get('confidence', 0)}%")
    
    def check_and_notify_email_security(self):
        """Verifica emails y notifica alertas de seguridad"""
        emails = self.email_manager.get_unread_emails()
        
        security_emails = [e for e in emails if e.get('is_security_alert')]
        
        for email in security_emails:
            notification = SecurityDetector.format_security_alert(
                email['security_analysis'],
                {
                    'sender_name': email['from'],
                    'text': f"{email['subject']}\n\n{email['body']}",
                    'source': 'Email'
                }
            )
            
            self.signal.send_message(notification)
            print(f"📧 Alerta de seguridad de email notificada: {email['subject'][:50]}")
    
    def send_scheduled_summary(self):
        """Envía resumen programado por Signal"""
        self.send_summary()
    
    def send_summary(self, hours: int = None):
        """Envía resumen por Signal"""
        print(f"📊 Generando resumen...")
        
        # Obtener datos
        messages = self.msg_manager.get_summary_data(hours=hours)
        emails = self.email_manager.get_unread_emails()
        
        # Separar alertas de seguridad
        security_messages = [m for m in messages if m.get('is_security_alert')]
        normal_messages = [m for m in messages if not m.get('is_security_alert')]
        
        security_emails = [e for e in emails if e.get('is_security_alert')]
        normal_emails = [e for e in emails if not e.get('is_security_alert')]
        
        if not messages and not emails:
            summary_text = "📊 RESUMEN\n\nNo hay mensajes ni emails nuevos desde el último resumen. ✨"
        else:
            # Generar resumen con Claude
            summary = self.claude.generate_summary(normal_messages, normal_emails)
            
            time_range = f"últimas {hours} horas" if hours else "desde último resumen"
            summary_text = f"📊 RESUMEN ({time_range})\n\n{summary}"
            
            # Agregar alertas de seguridad si las hay
            if security_messages or security_emails:
                summary_text += f"\n\n{'='*40}\n🔐 ALERTAS DE SEGURIDAD DETECTADAS\n{'='*40}\n"
                summary_text += f"\n📱 WhatsApp: {len(security_messages)} alertas"
                summary_text += f"\n📧 Email: {len(security_emails)} alertas\n"
                summary_text += "\n⚠️ Revisa las notificaciones individuales enviadas anteriormente."
        
        # Enviar por Signal
        self.signal.send_message(summary_text)
        
        # Marcar como resumidos
        if not hours:  # Solo marcar si es resumen completo
            self.msg_manager.mark_summarized()
        
        print("✓ Resumen enviado por Signal")
    
    def reply_to_whatsapp(self, target: str, message: str):
        """Envía respuesta a WhatsApp desde comando de Signal"""
        # Buscar mensajes del remitente
        messages = self.msg_manager.get_message_by_sender(target)
        
        if not messages:
            self.signal.send_message(f"❌ No encontré mensajes de '{target}'")
            return
        
        # Usar el más reciente
        last_msg = messages[-1]
        sender = last_msg['sender']
        
        # Enviar respuesta por WhatsApp
        self.wa.send_message(sender, message)
        
        # Confirmar por Signal
        self.signal.send_message(
            f"✓ Mensaje enviado a {last_msg['sender_name']} por WhatsApp:\n\n\"{message}\""
        )
        print(f"✓ Respuesta enviada a {last_msg['sender_name']} vía comando Signal")
    
    def search_messages(self, filter_text: str) -> str:
        """Busca mensajes y devuelve resultados"""
        messages = self.msg_manager.get_message_by_sender(filter_text)
        
        if not messages:
            return f"❌ No encontré mensajes con '{filter_text}'"
        
        results = f"🔍 RESULTADOS ({len(messages)} mensajes)\n\n"
        
        for msg in messages[-5:]:  # Últimos 5
            results += f"• {msg['sender_name']} [{msg['priority']}]\n"
            results += f"  {msg['text'][:100]}...\n\n"
        
        return results
    
    def stop(self):
        """Detiene el bot"""
        self.running = False
        self.email_manager.disconnect()
        self.signal.send_message("🛑 Bot detenido")
        print("✓ Bot detenido correctamente")

# ==================== EJECUCIÓN ====================
if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════╗
    ║  Bot WhatsApp con Control desde Signal       ║
    ╚═══════════════════════════════════════════════╝
    
    📱 WhatsApp: Recibe y responde mensajes
    💬 Signal: Tu panel de control
    
    Funcionalidades:
    ✓ Respuestas automáticas en WhatsApp con Claude
    ✓ Control total desde Signal
    ✓ Notificaciones urgentes por Signal
    ✓ Resúmenes programados vía Signal
    ✓ Comandos de voz desde WhatsApp
    ✓ Gestión priorizada de mensajes
    
    Configuración necesaria:
    1. Instalar Signal CLI: https://github.com/AsamK/signal-cli
    2. Registrar número en Signal CLI
    3. Actualizar Config con tus credenciales
    4. Instalar dependencias Python
    5. Escanear QR de WhatsApp
    
    Presiona Ctrl+C para detener
    """)
    
    try:
        bot = WhatsAppSignalAssistant()
        bot.start()
    except KeyboardInterrupt:
        print("\n\nBot detenido por el usuario")
    except Exception as e:
        print(f"\n❌ Error: {e}")