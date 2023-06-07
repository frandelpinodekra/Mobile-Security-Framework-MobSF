# from django.db.backends.signals import connection_created

# def activate_foreign_keys(sender, connection, **kwargs):
#     """Enable integrity constraint with sqlite."""
#     # if connection.vendor == 'sqlite':
#     cursor = connection.cursor()
#     cursor.execute('PRAGMA key = "0289b1bd8a76d7eff27825e343a21358";')

# connection_created.connect(activate_foreign_keys)