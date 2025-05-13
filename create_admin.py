# Импорт необходимых компонентов из основного приложения
from app import app, db, User, Role
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_admin():
    try:
        # Создание контекста приложения для работы с базой данных
        with app.app_context():
            logger.info("Начало создания ролей и администратора...")
            
            # Проверяем, существует ли уже роль администратора
            admin_role = Role.query.filter_by(name='Администратор').first()
            if not admin_role:
                # Создаем роль администратора с полными правами доступа
                admin_role = Role(
                    name='Администратор',
                    description='Полный доступ к системе',
                    can_view_users=True,
                    can_create_users=True,
                    can_edit_users=True,
                    can_delete_users=True,
                    can_view_visit_logs=True,
                    can_view_all_visit_logs=True
                )
                db.session.add(admin_role)
                logger.info("Создана роль администратора")

            # Проверяем, существует ли уже пользователь admin
            admin_user = User.query.filter_by(login='admin').first()
            if not admin_user:
                # Создаем пользователя-администратора
                admin_user = User(
                    login='admin',
                    first_name='Администратор',
                    role_id=admin_role.id
                )
                admin_user.set_password('Admin123!')
                db.session.add(admin_user)
                logger.info("Создан пользователь администратора")

            # Сохраняем изменения в базе данных
            db.session.commit()
            logger.info("Роли и администратор успешно созданы!")
            print("\nДанные для входа:")
            print("Логин: admin")
            print("Пароль: Admin123!")
            
    except Exception as e:
        logger.error(f"Ошибка при создании администратора: {str(e)}")
        db.session.rollback()
        raise

if __name__ == '__main__':
    create_admin() 