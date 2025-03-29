from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, MetaData, Table, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import json
import os
import pymysql
import ctypes

# Configuración de la aplicación
app = FastAPI(title="API TOPSIS")

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Primero crear la base de datos si no existe
def create_database():
    try:
        # Conectar a MySQL sin especificar una base de datos
        conn = pymysql.connect(
            host="127.0.0.1:3306",
            user="root",
            password="1234"
        )
        cursor = conn.cursor()

        # Crear la base de datos si no existe
        cursor.execute("CREATE DATABASE IF NOT EXISTS matrix_api")
        conn.commit()
        cursor.close()
        conn.close()
        print("Database check/creation successful")
    except Exception as e:
        print(f"Error creating database: {e}")
        raise e


# Llamar a la función para crear la base de datos
create_database()

# Ahora configurar SQLAlchemy con la base de datos que sabemos que existe
DATABASE_URL = "mysql+pymysql://root:1234@localhost/matrix_api"
engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Configuración de seguridad
SECRET_KEY = "clave_secreta_muy_segura_para_jwt"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Modelos de Pydantic
class UserBase(BaseModel):
    username: str
    email: str


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class MatrixData(BaseModel):
    attributes: List[str]
    candidates: List[str]
    weights: List[float]
    benefit_attributes: List[int]
    raw_data: List[List[float]]


# Alias para TopsisInput (para mantener compatibilidad con código existente)
TopsisInput = MatrixData


# Modelos de SQLAlchemy
class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(100))


class MatrixModel(Base):
    __tablename__ = "matrices"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    matrix_data = Column(Text)  # Almacenaremos la matriz como JSON en un campo de texto
    timestamp = Column(DateTime, default=datetime.utcnow)
    topsis_result = Column(Text, nullable=True)  # Campo para almacenar el resultado de TOPSIS


# Funciones para TOPSIS
def json_to_formatted_strings(data):
    attributes = data["attributes"]
    candidates = data["candidates"]
    raw_data = data["raw_data"]
    weights = data["weights"]
    benefit_attributes = data["benefit_attributes"]

    attributes_str = ','.join(attributes).encode('utf-8')
    candidates_str = ','.join(candidates).encode('utf-8')
    weights_str = ','.join(map(str, weights)).encode('utf-8')
    benefit_attributes_str = ','.join(map(str, benefit_attributes)).encode('utf-8')
    raw_data_str = ';'.join([','.join(map(str, row)) for row in raw_data]).encode('utf-8')

    return attributes_str, candidates_str, weights_str, benefit_attributes_str, raw_data_str


# Inicialización de la biblioteca TOPSIS
def initialize_topsis_lib():
    try:
        # Ruta de la librería .so
        dll_path = os.path.abspath("./topsislib.so")
        dll = ctypes.CDLL(dll_path)

        # Configurar tipos de argumentos y retorno
        dll.procesarDatos.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p
        ]
        dll.procesarDatos.restype = ctypes.c_char_p

        return dll
    except Exception as e:
        print(f"Error initializing TOPSIS library: {e}")
        return None


# Intentar cargar la biblioteca TOPSIS
topsis_lib = initialize_topsis_lib()


# Crear tablas
def create_tables():
    Base.metadata.create_all(bind=engine)


# Funciones de seguridad
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db: Session, username: str):
    return db.query(UserModel).filter(UserModel.username == username).first()


def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(lambda: SessionLocal())):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


# Dependency para obtener la sesión de la DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Endpoints
@app.post("/register", response_model=User)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = get_password_hash(user.password)
    db_user = UserModel(username=user.username, email=user.email, hashed_password=hashed_password)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
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
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/matrix")
async def save_matrix(matrix_data: MatrixData, current_user: UserModel = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    # Convertir la matriz a formato JSON y guardarla
    matrix_json = json.dumps({
        "attributes": matrix_data.attributes,
        "candidates": matrix_data.candidates,
        "weights": matrix_data.weights,
        "benefit_attributes": matrix_data.benefit_attributes,
        "raw_data": matrix_data.raw_data
    })

    # Calcular el resultado TOPSIS si la biblioteca está disponible
    topsis_result = None
    if topsis_lib:
        try:
            # Convertir JSON a cadenas formateadas para TOPSIS
            attributes_str, candidates_str, weights_str, benefit_attributes_str, raw_data_str = json_to_formatted_strings(
                matrix_data.dict())

            # Llamar a la función de la biblioteca .so
            result = topsis_lib.procesarDatos(attributes_str, candidates_str, weights_str, benefit_attributes_str,
                                              raw_data_str)

            # Convertir el resultado a una cadena de texto
            topsis_result = result.decode('utf-8')
        except Exception as e:
            print(f"Error al calcular TOPSIS: {e}")

    # Crear el registro en la base de datos
    new_matrix = MatrixModel(
        user_id=current_user.id,
        matrix_data=matrix_json,
        timestamp=datetime.utcnow(),
        topsis_result=topsis_result
    )

    db.add(new_matrix)
    db.commit()
    db.refresh(new_matrix)

    response = {
        "id": new_matrix.id,
        "timestamp": new_matrix.timestamp,
        "message": "Matrix saved successfully"
    }

    # Añadir el resultado TOPSIS a la respuesta si está disponible
    if topsis_result:
        response["topsis_result"] = topsis_result

    return response


@app.get("/matrix/{matrix_id}")
async def get_matrix(matrix_id: int, current_user: UserModel = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    matrix = db.query(MatrixModel).filter(MatrixModel.id == matrix_id, MatrixModel.user_id == current_user.id).first()

    if not matrix:
        raise HTTPException(status_code=404, detail="Matrix not found")

    response = {
        "id": matrix.id,
        "matrix": json.loads(matrix.matrix_data),
        "timestamp": matrix.timestamp
    }

    if matrix.topsis_result:
        response["topsis_result"] = matrix.topsis_result

    return response


@app.get("/matrices")
async def get_all_matrices(current_user: UserModel = Depends(get_current_user), db: Session = Depends(get_db)):
    matrices = db.query(MatrixModel).filter(MatrixModel.user_id == current_user.id).all()

    result = []
    for matrix in matrices:
        matrix_data = {
            "id": matrix.id,
            "matrix": json.loads(matrix.matrix_data),
            "timestamp": matrix.timestamp
        }

        if matrix.topsis_result:
            matrix_data["topsis_result"] = matrix.topsis_result

        result.append(matrix_data)

    return result


@app.post("/topsis")
async def run_topsis(data: TopsisInput):
    if not topsis_lib:
        raise HTTPException(
            status_code=500,
            detail="TOPSIS library not available"
        )

    try:
        # Convertir JSON a cadenas formateadas
        attributes_str, candidates_str, weights_str, benefit_attributes_str, raw_data_str = json_to_formatted_strings(
            data.dict())

        # Llamar a la función de la biblioteca .so
        result = topsis_lib.procesarDatos(attributes_str, candidates_str, weights_str, benefit_attributes_str,
                                          raw_data_str)

        # Convertir el resultado a una cadena de texto
        result_str = result.decode('utf-8')

        # Devolver el resultado como JSON
        return {"result": result_str}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error processing TOPSIS: {str(e)}"
        )


@app.post("/matrix/{matrix_id}/topsis")
async def calculate_topsis_for_matrix(
        matrix_id: int,
        current_user: UserModel = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    # Verificar que la biblioteca TOPSIS esté disponible
    if not topsis_lib:
        raise HTTPException(
            status_code=500,
            detail="TOPSIS library not available"
        )

    # Buscar la matriz en la base de datos
    matrix = db.query(MatrixModel).filter(MatrixModel.id == matrix_id, MatrixModel.user_id == current_user.id).first()

    if not matrix:
        raise HTTPException(status_code=404, detail="Matrix not found")

    try:
        # Obtener los datos de la matriz
        matrix_data = json.loads(matrix.matrix_data)

        # Convertir JSON a cadenas formateadas
        attributes_str, candidates_str, weights_str, benefit_attributes_str, raw_data_str = json_to_formatted_strings(
            matrix_data)

        # Llamar a la función de la biblioteca .so
        result = topsis_lib.procesarDatos(attributes_str, candidates_str, weights_str, benefit_attributes_str,
                                          raw_data_str)

        # Convertir el resultado a una cadena de texto
        result_str = result.decode('utf-8')

        # Actualizar el resultado de TOPSIS en la base de datos
        matrix.topsis_result = result_str
        db.commit()

        # Devolver el resultado como JSON
        return {
            "id": matrix.id,
            "topsis_result": result_str
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error processing TOPSIS: {str(e)}"
        )


# Inicialización
@app.on_event("startup")
async def startup():
    # Crear tablas
    create_tables()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)