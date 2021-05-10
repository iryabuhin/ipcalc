from peewee import *
import os

DB_NAME = 'db.sqlite'

database = SqliteDatabase(DB_NAME)


class BaseModel(Model):
    class Meta:
        database = database


class User(BaseModel):
    login = CharField(unique=True)
    password_hash = CharField()
    name = CharField()
    last_login = DateTimeField()


def create_tables():
    with database:
        database.create_tables([User])
