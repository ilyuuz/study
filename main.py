from datetime import datetime, timedelta, timezone
from typing import Union

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from typing_extensions import Annotated

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "618ef4f9e1855a0d9ae05b04ba990e78f90d65e92ce593d389ed47bf7c4af697"
# уникальный ключ для создания токена
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# время истечения токена


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str
# модель, используемая для аутентификации


class TokenData(BaseModel):
    username: Union[str, None] = None
# модель, хранящаяся в БД


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None
# модель для безопасного использования


class UserInDB(User):
    hashed_password: str
# модель, хранящаяся в БД, включает хеш пароля


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# утилита для хеширования пароля

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# схема авторизации

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)
# сравнивает пароль от пользователя и хеш пароля, хранящийся в БД. Возвращает True, если всё норм


def get_password_hash(password):
    return pwd_context.hash(password)
# хеширует пароль


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
# принимает логин и возвращает модель пользователя из БД


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user
# возвращает модель пользователя из БД, если пароль совпадает с хешем из БД (он предварительно расшифровывается функцией verify_password утилитой pwd_context)


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    # сюда функция login_to_access_token по пути "/login/ отправляет username в словаре data: {"sub" (субъет): username}
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    # добавляем дату истечения токена к словарю data
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    # делаем токен из логина и даты истечениия при помощи секретного ключа
    return encoded_jwt
# возвращаем токен


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # расшифровываем токен
        username: str = payload.get("sub")
        # Достаём из токена логин
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
        # 
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [{"item_id": "Foo", "owner": current_user.username}]
