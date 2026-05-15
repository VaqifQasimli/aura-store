"""
╔══════════════════════════════════════════╗
║        AURA Store — Python Backend       ║
║   FastAPI + SQLite + JWT + Gmail Email   ║
╚══════════════════════════════════════════╝
"""

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import smtplib, os, secrets
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

# ─── KONFİQURASİYA ────────────────────────────────────────────
SECRET_KEY            = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM             = "HS256"
TOKEN_EXPIRE_DAYS     = 7
DATABASE_URL          = os.getenv("DATABASE_URL", "sqlite:///./aurastore.db")
GMAIL_EMAIL           = os.getenv("GMAIL_EMAIL", "aura.store.0023@gmail.com")
GMAIL_APP_PASSWORD    = os.getenv("GMAIL_APP_PASSWORD", "")

# ─── VERİLƏNLƏR BAZASI ────────────────────────────────────────
engine        = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal  = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base          = declarative_base()
pwd_context   = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# ─── MODELLƏR ─────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id               = Column(Integer, primary_key=True, index=True)
    name             = Column(String(100), nullable=False)
    email            = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password  = Column(String(255), nullable=False)
    phone            = Column(String(20), nullable=True)
    address          = Column(String(500), nullable=True)
    city             = Column(String(100), nullable=True)
    is_active        = Column(Boolean, default=True)
    created_at       = Column(DateTime, default=datetime.utcnow)
    orders           = relationship("Order", back_populates="user")

class Product(Base):
    __tablename__ = "products"
    id           = Column(Integer, primary_key=True, index=True)
    name         = Column(String(200), nullable=False)
    category     = Column(String(50), nullable=False)
    price        = Column(Float, nullable=False)
    old_price    = Column(Float, nullable=True)
    emoji        = Column(String(10), default="📦")
    description  = Column(Text, nullable=True)
    rating       = Column(Float, default=4.5)
    review_count = Column(Integer, default=0)
    badge        = Column(String(20), nullable=True)
    stock        = Column(Integer, default=100)
    active       = Column(Boolean, default=True)
    created_at   = Column(DateTime, default=datetime.utcnow)

class Order(Base):
    __tablename__ = "orders"
    id             = Column(Integer, primary_key=True, index=True)
    order_number   = Column(String(20), unique=True, nullable=False)
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=True)
    user           = relationship("User", back_populates="orders")
    first_name     = Column(String(100))
    last_name      = Column(String(100))
    phone          = Column(String(20))
    email          = Column(String(255))
    address        = Column(String(500))
    city           = Column(String(100))
    payment_method = Column(String(20), default="CASH")
    note           = Column(Text, nullable=True)
    total_amount   = Column(Float)
    status         = Column(String(20), default="PENDING")
    created_at     = Column(DateTime, default=datetime.utcnow)
    items          = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")

class OrderItem(Base):
    __tablename__ = "order_items"
    id         = Column(Integer, primary_key=True, index=True)
    order_id   = Column(Integer, ForeignKey("orders.id"))
    order      = relationship("Order", back_populates="items")
    product_id = Column(Integer, ForeignKey("products.id"))
    product    = relationship("Product")
    quantity   = Column(Integer)
    unit_price = Column(Float)

Base.metadata.create_all(bind=engine)

# ─── PYDANTIC SCHEMALAR ────────────────────────────────────────
class RegisterSchema(BaseModel):
    name: str
    email: str
    password: str

class LoginSchema(BaseModel):
    email: str
    password: str

class ProfileSchema(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None

class CartItemSchema(BaseModel):
    product_id: int
    quantity: int

class OrderSchema(BaseModel):
    first_name: str
    last_name: str
    phone: str
    email: str
    address: str
    city: str
    payment_method: str = "CASH"
    note: Optional[str] = None
    items: List[CartItemSchema]

# ─── YARDIMÇI FUNKSİYALAR ─────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_pw(password: str) -> str:
    return pwd_context.hash(password)

def verify_pw(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(days=TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub": str(user_id), "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def get_user(authorization: str = Header(None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Daxil olun")
    try:
        payload  = jwt.decode(authorization.split(" ")[1], SECRET_KEY, algorithms=[ALGORITHM])
        user_id  = int(payload.get("sub"))
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Token etibarsızdır")
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="İstifadəçi tapılmadı")
    return user

def user_dict(u: User) -> dict:
    return {"id": u.id, "name": u.name, "email": u.email,
            "phone": u.phone, "address": u.address, "city": u.city,
            "created_at": u.created_at.isoformat()}

# ─── EMAİL ────────────────────────────────────────────────────
def send_email(order: Order):
    if not GMAIL_APP_PASSWORD:
        print("⚠️  GMAIL_APP_PASSWORD təyin edilməyib, email göndərilmir.")
        return
    try:
        rows = "".join(
            f"<tr style='border-bottom:1px solid #2a2a50'>"
            f"<td style='padding:12px'>{i.product.emoji} {i.product.name}</td>"
            f"<td style='padding:12px;text-align:center'>{i.quantity}</td>"
            f"<td style='padding:12px;text-align:right'>{i.unit_price:.2f} ₼</td>"
            f"<td style='padding:12px;text-align:right;font-weight:700;color:#8B5CF6'>{i.unit_price*i.quantity:.2f} ₼</td>"
            f"</tr>"
            for i in order.items
        )
        html = f"""<!DOCTYPE html><html><body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#07070F;">
<div style="max-width:620px;margin:30px auto;background:#0D0D1A;border-radius:16px;overflow:hidden;border:1px solid #1E1E3F;">
  <div style="background:linear-gradient(135deg,#7C3AED 0%,#4C1D95 50%,#C9A227 100%);padding:36px;text-align:center;">
    <div style="font-size:32px;margin-bottom:8px;">💎</div>
    <h1 style="color:white;margin:0;font-size:28px;letter-spacing:4px;">AURA STORE</h1>
    <p style="color:rgba(255,255,255,0.75);margin:8px 0 0;font-size:14px;letter-spacing:2px;">YENİ SİFARİŞ BİLDİRİŞİ</p>
  </div>
  <div style="padding:32px;">
    <div style="background:#131326;border-radius:12px;padding:20px;margin-bottom:24px;border:1px solid #1E1E3F;">
      <div style="font-size:12px;color:#6666AA;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;">Sifariş nömrəsi</div>
      <div style="font-size:22px;font-weight:700;color:#8B5CF6;">{order.order_number}</div>
      <div style="font-size:12px;color:#6666AA;margin-top:4px;">{order.created_at.strftime('%d.%m.%Y %H:%M')}</div>
    </div>
    <div style="background:#131326;border-radius:12px;padding:20px;margin-bottom:24px;border:1px solid #1E1E3F;">
      <div style="font-size:12px;color:#6666AA;text-transform:uppercase;letter-spacing:2px;margin-bottom:16px;">Müştəri</div>
      <table style="width:100%;border-collapse:collapse;font-size:14px;color:#EDEDFF;">
        <tr><td style="padding:4px 0;color:#6666AA;width:120px">Ad Soyad:</td><td>{order.first_name} {order.last_name}</td></tr>
        <tr><td style="padding:4px 0;color:#6666AA">Telefon:</td><td>{order.phone}</td></tr>
        <tr><td style="padding:4px 0;color:#6666AA">Email:</td><td>{order.email}</td></tr>
        <tr><td style="padding:4px 0;color:#6666AA">Ünvan:</td><td>{order.address}, {order.city}</td></tr>
        <tr><td style="padding:4px 0;color:#6666AA">Ödəniş:</td><td>{order.payment_method}</td></tr>
        {f'<tr><td style="padding:4px 0;color:#6666AA">Qeyd:</td><td>{order.note}</td></tr>' if order.note else ''}
      </table>
    </div>
    <div style="background:#131326;border-radius:12px;overflow:hidden;border:1px solid #1E1E3F;margin-bottom:24px;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;color:#EDEDFF;">
        <thead><tr style="background:#1A1A35;">
          <th style="padding:14px;text-align:left;color:#6666AA;font-weight:500">Məhsul</th>
          <th style="padding:14px;text-align:center;color:#6666AA;font-weight:500">Miqdar</th>
          <th style="padding:14px;text-align:right;color:#6666AA;font-weight:500">Qiymət</th>
          <th style="padding:14px;text-align:right;color:#6666AA;font-weight:500">Cəmi</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    <div style="background:linear-gradient(135deg,rgba(124,58,237,0.15),rgba(201,162,39,0.15));border:1px solid #7C3AED;border-radius:12px;padding:20px;text-align:right;">
      <span style="color:#6666AA;font-size:14px">Ümumi məbləğ: </span>
      <span style="font-size:26px;font-weight:700;color:#C9A227">{order.total_amount:.2f} ₼</span>
    </div>
  </div>
  <div style="padding:20px;text-align:center;border-top:1px solid #1E1E3F;">
    <p style="color:#6666AA;font-size:12px;margin:0">Bu bildiriş AURA Store sistemi tərəfindən avtomatik göndərilmişdir.</p>
  </div>
</div></body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🛍️ Yeni Sifariş {order.order_number} — AURA Store"
        msg["From"]    = GMAIL_EMAIL
        msg["To"]      = GMAIL_EMAIL
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(GMAIL_EMAIL, GMAIL_APP_PASSWORD)
            s.sendmail(GMAIL_EMAIL, GMAIL_EMAIL, msg.as_string())
        print(f"✅ Email göndərildi: {order.order_number}")
    except Exception as e:
        print(f"❌ Email xətası: {e}")

# ─── FASTAPI APP ───────────────────────────────────────────────
app = FastAPI(title="AURA Store API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── AUTH ROUTES ───────────────────────────────────────────────
@app.get("/")
def root():
    return {"app": "AURA Store API", "version": "1.0.0", "status": "✅ İşləyir"}

@app.post("/api/auth/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    if len(data.name.strip()) < 2:
        raise HTTPException(400, "Ad ən az 2 hərf olmalıdır")
    if len(data.password) < 6:
        raise HTTPException(400, "Şifrə ən az 6 simvol olmalıdır")
    if db.query(User).filter(User.email == data.email.lower().strip()).first():
        raise HTTPException(400, "Bu email artıq qeydiyyatdadır")
    user = User(name=data.name.strip(), email=data.email.lower().strip(), hashed_password=hash_pw(data.password))
    db.add(user); db.commit(); db.refresh(user)
    return {"success": True, "token": create_token(user.id), "user": user_dict(user)}

@app.post("/api/auth/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email.lower().strip()).first()
    if not user or not verify_pw(data.password, user.hashed_password):
        raise HTTPException(401, "Email və ya şifrə yanlışdır")
    return {"success": True, "token": create_token(user.id), "user": user_dict(user)}

@app.get("/api/auth/me")
def me(current_user: User = Depends(get_user)):
    return user_dict(current_user)

@app.put("/api/auth/profile")
def update_profile(data: ProfileSchema, current_user: User = Depends(get_user), db: Session = Depends(get_db)):
    if data.name:    current_user.name    = data.name.strip()
    if data.phone:   current_user.phone   = data.phone.strip()
    if data.address: current_user.address = data.address.strip()
    if data.city:    current_user.city    = data.city.strip()
    db.commit(); db.refresh(current_user)
    return {"success": True, "user": user_dict(current_user)}

# ─── PRODUCT ROUTES ────────────────────────────────────────────
@app.get("/api/products")
def products(category: str = None, search: str = None, min_price: float = None, max_price: float = None, db: Session = Depends(get_db)):
    q = db.query(Product).filter(Product.active == True)
    if category and category != "all": q = q.filter(Product.category == category)
    if search:     q = q.filter(Product.name.ilike(f"%{search}%"))
    if min_price:  q = q.filter(Product.price >= min_price)
    if max_price:  q = q.filter(Product.price <= max_price)
    return [{"id":p.id,"name":p.name,"category":p.category,"price":p.price,"old_price":p.old_price,
             "emoji":p.emoji,"description":p.description,"rating":p.rating,"review_count":p.review_count,
             "badge":p.badge,"stock":p.stock} for p in q.all()]

@app.get("/api/products/{pid}")
def product(pid: int, db: Session = Depends(get_db)):
    p = db.query(Product).filter(Product.id == pid, Product.active == True).first()
    if not p: raise HTTPException(404, "Məhsul tapılmadı")
    return {"id":p.id,"name":p.name,"category":p.category,"price":p.price,"old_price":p.old_price,
            "emoji":p.emoji,"description":p.description,"rating":p.rating,"review_count":p.review_count,
            "badge":p.badge,"stock":p.stock}

# ─── ORDER ROUTES ──────────────────────────────────────────────
@app.post("/api/orders")
def create_order(data: OrderSchema, current_user: User = Depends(get_user), db: Session = Depends(get_db)):
    count        = db.query(Order).count()
    order_number = f"#AURA-{1001 + count}"
    total        = 0
    pairs        = []

    for ci in data.items:
        p = db.query(Product).filter(Product.id == ci.product_id).first()
        if not p: raise HTTPException(404, f"Məhsul tapılmadı: {ci.product_id}")
        if p.stock < ci.quantity: raise HTTPException(400, f"'{p.name}' anbarda yoxdur (qalan: {p.stock})")
        total += p.price * ci.quantity
        pairs.append((p, ci.quantity))

    order = Order(order_number=order_number, user_id=current_user.id,
                  first_name=data.first_name, last_name=data.last_name,
                  phone=data.phone, email=data.email, address=data.address,
                  city=data.city, payment_method=data.payment_method,
                  note=data.note, total_amount=total)
    db.add(order); db.commit(); db.refresh(order)

    for p, qty in pairs:
        db.add(OrderItem(order_id=order.id, product_id=p.id, quantity=qty, unit_price=p.price))
        p.stock -= qty
    db.commit(); db.refresh(order)

    send_email(order)
    return {"success": True, "order_number": order.order_number, "order_id": order.id,
            "total_amount": order.total_amount, "message": "Sifarişiniz qəbul edildi!"}

@app.get("/api/orders/my")
def my_orders(current_user: User = Depends(get_user), db: Session = Depends(get_db)):
    orders = db.query(Order).filter(Order.user_id == current_user.id).order_by(Order.created_at.desc()).all()
    return [{"id":o.id,"order_number":o.order_number,"total_amount":o.total_amount,"status":o.status,
             "city":o.city,"payment_method":o.payment_method,"created_at":o.created_at.isoformat(),
             "items":[{"name":i.product.name,"emoji":i.product.emoji,"qty":i.quantity,"price":i.unit_price} for i in o.items]}
            for o in orders]

# ─── NÜMUNƏ MƏHSULLAR ──────────────────────────────────────────
@app.on_event("startup")
def seed():
    db = SessionLocal()
    try:
        if db.query(Product).count() > 0: return
        items = [
            ("Klassik Köynək","geyim",25,35,"👔",4.5,128,"Endirim",50,"Premium pambıq klassik köynək"),
            ("Casual T-shirt","geyim",15,None,"👕",4.2,89,"Yeni",80,"Rahat gündəlik t-shirt"),
            ("Kişi Kostyum","geyim",180,220,"🤵",4.8,56,"Endirim",15,"Elegant kişi kostyumu"),
            ("Qadın Paltarı","geyim",55,None,"👗",4.6,203,None,40,"Şık qadın paltarı"),
            ("Dəri Ayaqqabı","geyim",95,120,"👞",4.4,77,"Endirim",25,"Genuine dəri ayaqqabı"),
            ("Gödəkçə","geyim",140,170,"🧥",4.3,45,None,20,"Qış üçün gödəkçə"),
            ("Smartfon Pro Max","elektronika",999,1199,"📱",4.9,312,"Endirim",10,"Ən son model smartfon"),
            ("Qulaqlıq ANC","elektronika",199,None,"🎧",4.7,188,"Yeni",30,"Aktiv səs-küy söndürmə"),
            ("Noutbuk Ultra","elektronika",1450,1700,"💻",4.8,95,"Endirim",8,"Ultra slim noutbuk"),
            ("Smart Saat","elektronika",249,299,"⌚",4.5,143,None,22,"Sağlamlıq izləmə saatı"),
            ("Portativ Dinamik","elektronika",85,None,"🔊",4.4,67,"Yeni",35,"360° portativ dinamik"),
            ("Yuxu Dəsti","ev",65,None,"🛏️",4.6,231,None,18,"Premium ipəksi yuxu dəsti"),
            ("Dekorativ Yastıq","ev",18,25,"🛋️",4.2,88,"Endirim",60,"Rəngarəng dekorativ yastıq"),
            ("Aromatik Şam","ev",22,None,"🕯️",4.8,156,"Yeni",45,"Əl işi aromatik şam"),
            ("Mətbəx Dəsti","ev",110,140,"🍳",4.5,74,"Endirim",12,"Tam mətbəx qab dəsti"),
            ("Futbol Topu","idman",45,None,"⚽",4.4,63,None,40,"Professional futbol topu"),
            ("Yoga Matı","idman",35,50,"🧘",4.7,119,"Endirim",28,"Non-slip yoga matı"),
            ("İdman Çantası","idman",55,None,"🎒",4.3,82,"Yeni",33,"Su keçirməyən idman çantası"),
        ]
        db.add_all([Product(name=n,category=c,price=pr,old_price=op,emoji=e,rating=r,review_count=rc,
                            badge=b,stock=s,description=d) for n,c,pr,op,e,r,rc,b,s,d in items])
        db.commit()
        print(f"✅ {len(items)} nümunə məhsul əlavə edildi")
    finally:
        db.close()