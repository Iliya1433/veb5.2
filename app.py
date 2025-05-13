from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
import os
from dotenv import load_dotenv
import logging
from functools import wraps
import csv
from io import StringIO, BytesIO
import tempfile

#Аутентификация во Flask-Этот процесс предотвращает попадание неавторизованных пользователей на непредназначенные для них страницы. 
# Собственную систему аутентификации можно создать с помощью куки и хэширования паролей.

#Завершение сеансов пользователей Функция logout_user() во Flask-Login завершает сеанс пользователя, удаляя его идентификатор из сессии

#Хэширование паролей включает несколько шагов: при регистрации пользователь передает пароль, который хэшируется и сохраняется в базе данных. 
# При авторизации хэш создается снова и сравнивается с сохраненным. Если они совпадают, доступ предоставляется, иначе возникает ошибка. 
# Flask использует пакет Werkzeug, который предлагает функции для хэширования паролей.

# Настройка логирования для отслеживания работы приложения
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Загрузка переменных окружения из .env файла
load_dotenv()

# Инициализация Flask приложения с настройкой путей к шаблонам и конфигурационным файлам
app = Flask(__name__, 
    template_folder='templates',
    instance_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance'),
    instance_relative_config=True)

# Конфигурация приложения
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')  # Секретный ключ для сессий
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')  # URL базы данных
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Отключение отслеживания изменений в SQLAlchemy

# Инициализация расширений
db = SQLAlchemy(app)  # Инициализация базы данных
login_manager = LoginManager()  # Инициализация менеджера авторизации
login_manager.init_app(app)
login_manager.login_view = 'login'  # Указание страницы для входа

# Модель ролей пользователей
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Уникальный идентификатор роли
    name = db.Column(db.String(50), nullable=False)  # Название роли
    description = db.Column(db.String(200))  # Описание роли
    users = db.relationship('User', backref='role', lazy=True)  # Связь с пользователями
    
    # Добавляем поля для прав доступа
    can_view_users = db.Column(db.Boolean, default=False)
    can_create_users = db.Column(db.Boolean, default=False)
    can_edit_users = db.Column(db.Boolean, default=False)
    can_delete_users = db.Column(db.Boolean, default=False)
    can_view_visit_logs = db.Column(db.Boolean, default=False)
    can_view_all_visit_logs = db.Column(db.Boolean, default=False)

    def has_permission(self, permission):
        """Проверка наличия конкретного права у роли"""
        return getattr(self, f'can_{permission}', False)

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Уникальный идентификатор пользователя
    login = db.Column(db.String(50), unique=True, nullable=False)  # Логин пользователя
    password_hash = db.Column(db.String(128), nullable=False)  # Хеш пароля
    last_name = db.Column(db.String(50))  # Фамилия
    first_name = db.Column(db.String(50), nullable=False)  # Имя
    middle_name = db.Column(db.String(50))  # Отчество
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))  # Связь с ролью
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Дата создания
    visit_logs = db.relationship('VisitLog', backref='user', lazy=True)  # Связь с логами посещений

    # Метод для установки пароля с хешированием
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Метод для проверки пароля
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Свойство для проверки, является ли пользователь администратором
    @property
    def is_admin(self):
        return self.role and self.role.name == 'Администратор'

    def has_permission(self, permission):
        """Проверка наличия права у пользователя"""
        if self.is_admin:
            return True
        return self.role and self.role.has_permission(permission)

    def can_view_own_visit_logs(self):
        """Проверка права на просмотр своих логов посещений"""
        return self.has_permission('view_visit_logs')

    def can_view_all_visit_logs(self):
        """Проверка права на просмотр всех логов посещений"""
        return self.has_permission('view_all_visit_logs')

# Модель логов посещений
class VisitLog(db.Model):
    __tablename__ = 'visit_log'  # Явное указание имени таблицы
    id = db.Column(db.Integer, primary_key=True)  # Уникальный идентификатор записи
    path = db.Column(db.String(100), nullable=False)  # Путь посещенной страницы
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Связь с пользователем
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Время посещения

# Декоратор для проверки прав доступа
def check_rights(required_rights):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Проверка аутентификации
            if not current_user.is_authenticated:
                flash('У вас недостаточно прав для доступа к данной странице.')
                return redirect(url_for('index'))
            
            # Администраторы имеют доступ ко всему
            if current_user.is_admin:
                return f(*args, **kwargs)
            
            # Проверка прав на просмотр собственного профиля
            if 'view_own_profile' in required_rights and kwargs.get('user_id') == current_user.id:
                return f(*args, **kwargs)
            
            # Проверка прав на редактирование собственного профиля
            if 'edit_own_profile' in required_rights and kwargs.get('user_id') == current_user.id:
                return f(*args, **kwargs)
            
            flash('У вас недостаточно прав для доступа к данной странице.')
            return redirect(url_for('index'))
        return decorated_function
    return decorator

# Middleware для логирования посещений
@app.before_request
def log_visit():
    try:
        if request.endpoint and 'static' not in request.endpoint:
            visit_log = VisitLog(
                path=request.path,
                user_id=current_user.id if current_user.is_authenticated else None
            )
            db.session.add(visit_log)
            db.session.commit()
    except Exception as e:
        logger.error(f"Ошибка при логировании посещения: {str(e)}")
        db.session.rollback()

# Функция загрузки пользователя для Flask-Login
#Для запуска Flask-Login нужно импортировать класс LoginManager из пакета flask_login и создать новый экземпляр LoginManager.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Функция валидации пароля
def validate_password(password):
    # Проверка длины пароля
    if len(password) < 8 or len(password) > 128:
        return False, "Password must be between 8 and 128 characters"
    # Проверка наличия заглавных букв
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    # Проверка наличия строчных букв
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    # Проверка наличия цифр
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    # Проверка отсутствия пробелов
    if re.search(r'\s', password):
        return False, "Password cannot contain spaces"
    # Проверка допустимых символов
    if not re.match(r'^[a-zA-Zа-яА-Я0-9~!?@#$%^&*_\-+()\[\]{}><\/\\|"\'\.,:;]+$', password):
        return False, "Password contains invalid characters"
    return True, ""

# Маршрут главной страницы
@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

# Маршрут страницы входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        user = User.query.filter_by(login=login).first()
        
        # Проверка учетных данных
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid login or password')
    return render_template('login.html')

# Маршрут выхода из системы
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Маршрут просмотра профиля пользователя
@app.route('/user/<int:user_id>')
@login_required
@check_rights(['view_own_profile'])
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)

# Маршрут создания нового пользователя
@app.route('/user/new', methods=['GET', 'POST'])
@login_required
@check_rights(['create_user'])
def create_user():
    if not current_user.is_admin:
        flash('У вас недостаточно прав для доступа к данной странице.')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        # Получение данных из формы
        login = request.form.get('login')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        middle_name = request.form.get('middle_name')
        role_id = request.form.get('role_id')

        # Валидация обязательных полей
        if not login or not password or not first_name:
            flash('Required fields cannot be empty')
            return render_template('user_form.html', roles=Role.query.all())

        # Валидация логина
        if not re.match(r'^[a-zA-Z0-9]{5,}$', login):
            flash('Login must be at least 5 characters long and contain only Latin letters and numbers')
            return render_template('user_form.html', roles=Role.query.all())

        # Валидация пароля
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message)
            return render_template('user_form.html', roles=Role.query.all())

        # Создание нового пользователя
        user = User(
            login=login,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            role_id=role_id if role_id else None
        )
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()
            flash('User created successfully')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating user')
            return render_template('user_form.html', roles=Role.query.all())

    return render_template('user_form.html', roles=Role.query.all())

# Маршрут редактирования пользователя
@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@check_rights(['edit_own_profile'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Проверка прав на редактирование
    if not current_user.is_admin and current_user.id != user_id:
        flash('У вас недостаточно прав для доступа к данной странице.')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        # Получение данных из формы
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        middle_name = request.form.get('middle_name')
        role_id = request.form.get('role_id')

        # Валидация обязательных полей
        if not first_name:
            flash('First name cannot be empty')
            return render_template('user_form.html', user=user, roles=Role.query.all())

        # Обновление данных пользователя
        user.first_name = first_name
        user.last_name = last_name
        user.middle_name = middle_name
        
        # Обновление роли (только для администраторов)
        if current_user.is_admin:
            user.role_id = role_id if role_id else None

        try:
            db.session.commit()
            flash('User updated successfully')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating user')
            return render_template('user_form.html', user=user, roles=Role.query.all())

    return render_template('user_form.html', user=user, roles=Role.query.all())

# Маршрут удаления пользователя
@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@check_rights(['delete_user'])
def delete_user(user_id):
    if not current_user.is_admin:
        flash('У вас недостаточно прав для доступа к данной странице.')
        return redirect(url_for('index'))
        
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user')
    return redirect(url_for('index'))

# Маршрут изменения пароля
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Проверка текущего пароля
        if not current_user.check_password(current_password):
            flash('Current password is incorrect')
            return render_template('change_password.html')

        # Проверка совпадения новых паролей
        if new_password != confirm_password:
            flash('New passwords do not match')
            return render_template('change_password.html')

        # Валидация нового пароля
        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message)
            return render_template('change_password.html')

        # Обновление пароля
        current_user.set_password(new_password)
        try:
            db.session.commit()
            flash('Password changed successfully')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error changing password')
            return render_template('change_password.html')

    return render_template('change_password.html')

# Маршрут просмотра логов посещений
@app.route('/visit-logs')
@login_required
def visit_logs():
    # Проверяем права доступа к журналу посещений
    if not current_user.can_view_own_visit_logs() and not current_user.can_view_all_visit_logs():
        flash('У вас недостаточно прав для просмотра журнала посещений.')
        return redirect(url_for('index'))

    # Получаем номер страницы из параметров запроса
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Количество записей на странице

    # Формируем запрос в зависимости от прав пользователя
    if current_user.can_view_all_visit_logs():
        # Администраторы и пользователи с правом просмотра всех логов видят все записи
        logs = VisitLog.query.order_by(VisitLog.created_at.desc()).paginate(page=page, per_page=per_page)
    else:
        # Обычные пользователи видят только свои записи
        logs = VisitLog.query.filter_by(user_id=current_user.id).order_by(VisitLog.created_at.desc()).paginate(page=page, per_page=per_page)

    return render_template('visit_logs.html', logs=logs)

# Маршрут для отображения статистики посещений по страницам
@app.route('/visit-logs/by-page')
@login_required
def visit_logs_by_page():
    # Получаем статистику посещений по страницам, отсортированную по убыванию количества посещений
    page_stats = db.session.query(
        VisitLog.path,
        db.func.count(VisitLog.id).label('count')
    ).group_by(VisitLog.path).order_by(db.desc('count')).all()
    
    return render_template('visit_logs_by_page.html', page_stats=page_stats)

# Маршрут для отображения статистики посещений по пользователям
@app.route('/visit-logs/by-user')
@login_required
def visit_logs_by_user():
    # Получаем статистику посещений по пользователям, отсортированную по убыванию количества посещений
    user_stats = db.session.query(
        User,
        db.func.count(VisitLog.id).label('count')
    ).outerjoin(VisitLog).group_by(User.id).order_by(db.desc('count')).all()
    
    return render_template('visit_logs_by_user.html', user_stats=user_stats)

# Маршрут для экспорта статистики посещений по страницам в CSV
@app.route('/visit-logs/by-page/export')
@login_required
def export_visit_logs_by_page():
    """
    Экспорт статистики посещений по страницам в CSV файл.
    
    Функция выполняет следующие действия:
    1. Проверяет права доступа (только для администраторов)
    2. Получает статистику посещений из базы данных
    3. Создает временный CSV файл с кодировкой UTF-8 с BOM
    4. Записывает данные в файл
    5. Отправляет файл пользователю
    6. Удаляет временный файл после отправки
    
    Returns:
        Response: CSV файл для скачивания или редирект в случае ошибки
    """
    try:
        # Проверка прав доступа
        if not current_user.is_admin:
            flash('У вас недостаточно прав для доступа к данной странице.')
            return redirect(url_for('index'))

        logger.info("Начало экспорта статистики по страницам")
        
        # Получение статистики посещений по страницам
        # Группировка по пути и подсчет количества посещений
        page_stats = db.session.query(
            VisitLog.path,
            db.func.count(VisitLog.id).label('count')
        ).group_by(VisitLog.path).order_by(db.desc('count')).all()
        
        logger.info(f"Получено {len(page_stats)} записей для экспорта")
        
        # Создание временного файла с кодировкой UTF-8 с BOM
        # delete=False позволяет файлу существовать после закрытия
        temp_file = tempfile.NamedTemporaryFile(
            mode='w',  # Режим записи
            delete=False,  # Не удалять файл после закрытия
            encoding='utf-8-sig',  # Кодировка UTF-8 с BOM
            suffix='.csv'  # Расширение файла
        )
        
        try:
            # Создание CSV writer с настройками
            writer = csv.writer(
                temp_file,
                delimiter=';',  # Разделитель полей
                quoting=csv.QUOTE_MINIMAL  # Минимальное экранирование
            )
            
            # Запись заголовков
            writer.writerow(['№', 'Страница', 'Количество посещений'])
            
            # Запись данных с нумерацией
            for i, (path, count) in enumerate(page_stats, 1):
                writer.writerow([i, path, count])
            
            # Закрытие файла перед отправкой
            temp_file.close()
            
            logger.info("CSV файл успешно создан")
            
            # Отправка файла пользователю
            return send_file(
                temp_file.name,  # Путь к файлу
                mimetype='text/csv; charset=utf-8-sig',  # MIME-тип с указанием кодировки
                as_attachment=True,  # Отправка как вложение
                download_name='visit_stats_by_page.csv'  # Имя файла при скачивании
            )
        finally:
            # Удаление временного файла после отправки
            try:
                os.unlink(temp_file.name)
            except Exception as e:
                logger.error(f"Ошибка при удалении временного файла: {str(e)}")
                
    except Exception as e:
        # Логирование и обработка ошибок
        logger.error(f"Ошибка при экспорте статистики по страницам: {str(e)}")
        flash('Произошла ошибка при экспорте данных')
        return redirect(url_for('visit_logs_by_page'))

# Маршрут для экспорта статистики посещений по пользователям в CSV
@app.route('/visit-logs/by-user/export')
@login_required
def export_visit_logs_by_user():
    """
    Экспорт статистики посещений по пользователям в CSV файл.
    
    Функция выполняет следующие действия:
    1. Проверяет права доступа (только для администраторов)
    2. Получает статистику посещений из базы данных
    3. Создает временный CSV файл с кодировкой UTF-8 с BOM
    4. Записывает данные в файл
    5. Отправляет файл пользователю
    6. Удаляет временный файл после отправки
    
    Returns:
        Response: CSV файл для скачивания или редирект в случае ошибки
    """
    try:
        # Проверка прав доступа
        if not current_user.is_admin:
            flash('У вас недостаточно прав для доступа к данной странице.')
            return redirect(url_for('index'))

        logger.info("Начало экспорта статистики по пользователям")
        
        # Получение статистики посещений по пользователям
        # Группировка по пользователю и подсчет количества посещений
        user_stats = db.session.query(
            User,
            db.func.count(VisitLog.id).label('count')
        ).outerjoin(VisitLog).group_by(User.id).order_by(db.desc('count')).all()
        
        logger.info(f"Получено {len(user_stats)} записей для экспорта")
        
        # Создание временного файла с кодировкой UTF-8 с BOM
        temp_file = tempfile.NamedTemporaryFile(
            mode='w',
            delete=False,
            encoding='utf-8-sig',
            suffix='.csv'
        )
        
        try:
            # Создание CSV writer с настройками
            writer = csv.writer(
                temp_file,
                delimiter=';',
                quoting=csv.QUOTE_MINIMAL
            )
            
            # Запись заголовков
            writer.writerow(['№', 'Пользователь', 'Количество посещений'])
            
            # Запись данных с форматированием ФИО
            for i, (user, count) in enumerate(user_stats, 1):
                # Формирование полного имени пользователя
                user_name = f"{user.last_name or ''} {user.first_name} {user.middle_name or ''}".strip() if user else "Неаутентифицированный пользователь"
                writer.writerow([i, user_name, count])
            
            # Закрытие файла перед отправкой
            temp_file.close()
            
            logger.info("CSV файл успешно создан")
            
            # Отправка файла пользователю
            return send_file(
                temp_file.name,
                mimetype='text/csv; charset=utf-8-sig',
                as_attachment=True,
                download_name='visit_stats_by_user.csv'
            )
        finally:
            # Удаление временного файла после отправки
            try:
                os.unlink(temp_file.name)
            except Exception as e:
                logger.error(f"Ошибка при удалении временного файла: {str(e)}")
                
    except Exception as e:
        # Логирование и обработка ошибок
        logger.error(f"Ошибка при экспорте статистики по пользователям: {str(e)}")
        flash('Произошла ошибка при экспорте данных')
        return redirect(url_for('visit_logs_by_user'))

# Обработчик ошибки 500 (внутренняя ошибка сервера)
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error=error), 500

# Обработчик ошибки 404 (страница не найдена)
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error=error), 404

with app.app_context():
    try:
        logger.info("Начало инициализации базы данных...")
        # Создаем все таблицы
        db.create_all()
        logger.info("База данных инициализирована успешно")
    except Exception as e:
        logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
        raise  # Пробрасываем ошибку дальше для отладки

if __name__ == '__main__':
    app.run(debug=True) 