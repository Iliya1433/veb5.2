# Импорт необходимых компонентов из основного приложения
from app import app, db, User, Role

def create_admin():
    # Создание контекста приложения для работы с базой данных
    with app.app_context():
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

        # Создаем роль обычного пользователя с ограниченными правами
        user_role = Role(
            name='Пользователь',
            description='Ограниченный доступ к системе',
            can_view_users=True,
            can_view_visit_logs=True,
            can_view_all_visit_logs=False
        )
        db.session.add(user_role)

        # Создаем роль модератора с расширенными правами
        moderator_role = Role(
            name='Модератор',
            description='Расширенный доступ к системе',
            can_view_users=True,
            can_create_users=True,
            can_edit_users=True,
            can_delete_users=False,
            can_view_visit_logs=True,
            can_view_all_visit_logs=True
        )
        db.session.add(moderator_role)

        db.session.commit()

        # Создаем пользователя-администратора с предустановленными учетными данными
        admin = User(
            login='admin',
            first_name='Администратор',
            role_id=admin_role.id
        )
        # Установка пароля с хешированием
        admin.set_password('Admin123!')
        
        # Сохранение пользователя в базе данных
        db.session.add(admin)
        db.session.commit()
        print("Роли и администратор успешно созданы!")
        print("Логин: admin")
        print("Пароль: Admin123!")

# Запуск создания администратора при прямом выполнении скрипта
if __name__ == '__main__':
    create_admin() 