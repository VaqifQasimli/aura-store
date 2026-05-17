from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, List
import hashlib, os, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SECRET_KEY         = os.getenv("SECRET_KEY", "aura-secret-2025-xyz")
DATABASE_URL       = os.getenv("DATABASE_URL", "sqlite:///./aurastore.db")
GMAIL_EMAIL        = os.getenv("GMAIL_EMAIL", "aura.store.0023@gmail.com")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")
ADMIN_PASSWORD     = os.getenv("ADMIN_PASSWORD", "aura-admin-2025")

engine       = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_pw(plain, hashed):
    return hashlib.sha256(plain.encode()).hexdigest() == hashed

def create_token(user_id, days=7):
    import base64, json, hmac
    payload = json.dumps({"sub": user_id, "exp": (datetime.utcnow() + timedelta(days=days)).isoformat()})
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(payload.encode()).decode() + "." + sig

def create_refresh_token(user_id):
    return create_token(user_id, days=30)

def create_admin_token():
    import base64, json, hmac
    payload = json.dumps({"sub": "admin", "role": "admin", "exp": (datetime.utcnow() + timedelta(hours=12)).isoformat()})
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(payload.encode()).decode() + "." + sig

def verify_token(token):
    import base64, json, hmac
    try:
        parts = token.split(".")
        payload_b64, sig = ".".join(parts[:-1]), parts[-1]
        payload = base64.b64decode(payload_b64.encode()).decode()
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if sig != expected: raise ValueError()
        data = json.loads(payload)
        if datetime.fromisoformat(data["exp"]) < datetime.utcnow(): raise ValueError()
        return int(data["sub"])
    except:
        raise HTTPException(status_code=401, detail="Token etibarsızdır")

def verify_admin_token(token):
    import base64, json, hmac
    try:
        parts = token.split(".")
        payload_b64, sig = ".".join(parts[:-1]), parts[-1]
        payload = base64.b64decode(payload_b64.encode()).decode()
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if sig != expected: return False
        data = json.loads(payload)
        if datetime.fromisoformat(data["exp"]) < datetime.utcnow(): return False
        return data.get("role") == "admin"
    except:
        return False

class User(Base):
    __tablename__ = "users"
    id              = Column(Integer, primary_key=True, index=True)
    name            = Column(String(100), nullable=False)
    email           = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    phone           = Column(String(20), nullable=True)
    address         = Column(String(500), nullable=True)
    city            = Column(String(100), nullable=True)
    is_active       = Column(Boolean, default=True)
    created_at      = Column(DateTime, default=datetime.utcnow)
    orders          = relationship("Order", back_populates="user")

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

class RegisterSchema(BaseModel):
    name: str
    email: str
    password: str

class LoginSchema(BaseModel):
    email: str
    password: str

class RefreshSchema(BaseModel):
    refresh_token: str

class AdminLoginSchema(BaseModel):
    password: str

class ProfileSchema(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None

class ProductSchema(BaseModel):
    name: str
    category: str
    price: float
    old_price: Optional[float] = None
    emoji: Optional[str] = "📦"
    description: Optional[str] = None
    badge: Optional[str] = None
    stock: Optional[int] = 100

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

class OrderStatusSchema(BaseModel):
    status: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(authorization: str = Header(default=None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Daxil olun")
    user_id = verify_token(authorization.split(" ")[1])
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="İstifadəçi tapılmadı")
    return user

def get_admin(authorization: str = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Admin girişi tələb olunur")
    if not verify_admin_token(authorization.split(" ")[1]):
        raise HTTPException(status_code=401, detail="Admin token etibarsızdır")
    return True

def user_dict(u):
    return {"id":u.id,"name":u.name,"email":u.email,"phone":u.phone,
            "address":u.address,"city":u.city,"created_at":u.created_at.isoformat()}

def product_dict(p):
    return {"id":p.id,"name":p.name,"category":p.category,"price":p.price,
            "old_price":p.old_price,"emoji":p.emoji,"description":p.description,
            "rating":p.rating,"review_count":p.review_count,"badge":p.badge,
            "stock":p.stock,"active":p.active}

def send_email(order):
    if not GMAIL_APP_PASSWORD:
        print("⚠️ GMAIL_APP_PASSWORD yoxdur"); return
    try:
        rows = "".join(f"<tr><td style='padding:10px'>{i.product.emoji} {i.product.name}</td><td style='padding:10px;text-align:center'>{i.quantity}</td><td style='padding:10px;text-align:right'>{i.unit_price*i.quantity:.2f} ₼</td></tr>" for i in order.items)
        html = f"""<html><body style="font-family:Arial;background:#07070F;padding:20px"><div style="max-width:600px;margin:0 auto;background:#0D0D1A;border-radius:16px;overflow:hidden"><div style="background:linear-gradient(135deg,#7C3AED,#C9A227);padding:30px;text-align:center"><h1 style="color:white;margin:0;letter-spacing:4px">💎 AURA STORE</h1><p style="color:rgba(255,255,255,.8);margin:8px 0 0">YENİ SİFARİŞ — {order.order_number}</p></div><div style="padding:30px;color:#EDEDFF"><p><b>Ad:</b> {order.first_name} {order.last_name}</p><p><b>Telefon:</b> {order.phone}</p><p><b>Ünvan:</b> {order.address}, {order.city}</p><p><b>Ödəniş:</b> {order.payment_method}</p><table style="width:100%;border-collapse:collapse;margin-top:20px"><tr style="background:#1A1A35"><th style="padding:10px;text-align:left">Məhsul</th><th style="padding:10px">Miqdar</th><th style="padding:10px">Cəmi</th></tr>{rows}</table><div style="text-align:right;margin-top:20px;font-size:22px;font-weight:700;color:#C9A227">Ümumi: {order.total_amount:.2f} ₼</div></div></div></body></html>"""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🛍️ Yeni Sifariş {order.order_number} — AURA Store"
        msg["From"] = GMAIL_EMAIL; msg["To"] = GMAIL_EMAIL
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(GMAIL_EMAIL, GMAIL_APP_PASSWORD)
            s.sendmail(GMAIL_EMAIL, GMAIL_EMAIL, msg.as_string())
        print(f"✅ Email: {order.order_number}")
    except Exception as e:
        print(f"❌ Email xətası: {e}")

app = FastAPI(title="AURA Store API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def root():
    return {"app": "AURA Store API", "version": "2.0.0", "status": "✅ İşləyir"}

@app.post("/api/auth/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    if len(data.name.strip()) < 2: raise HTTPException(400, "Ad ən az 2 hərf olmalıdır")
    if len(data.password) < 6: raise HTTPException(400, "Şifrə ən az 6 simvol olmalıdır")
    if db.query(User).filter(User.email == data.email.lower().strip()).first(): raise HTTPException(400, "Bu email artıq qeydiyyatdadır")
    user = User(name=data.name.strip(), email=data.email.lower().strip(), hashed_password=hash_pw(data.password))
    db.add(user); db.commit(); db.refresh(user)
    return {"success":True,"token":create_token(user.id),"refresh_token":create_refresh_token(user.id),"user":user_dict(user)}

@app.post("/api/auth/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email.lower().strip()).first()
    if not user or not verify_pw(data.password, user.hashed_password): raise HTTPException(401, "Email və ya şifrə yanlışdır")
    return {"success":True,"token":create_token(user.id),"refresh_token":create_refresh_token(user.id),"user":user_dict(user)}

@app.post("/api/auth/refresh")
def refresh(data: RefreshSchema, db: Session = Depends(get_db)):
    user_id = verify_token(data.refresh_token)
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user: raise HTTPException(401, "İstifadəçi tapılmadı")
    return {"success":True,"token":create_token(user.id),"refresh_token":create_refresh_token(user.id),"user":user_dict(user)}

@app.get("/api/auth/me")
def me(current_user: User = Depends(get_user)):
    return user_dict(current_user)

@app.put("/api/auth/profile")
def update_profile(data: ProfileSchema, current_user: User = Depends(get_user), db: Session = Depends(get_db)):
    if data.name: current_user.name = data.name.strip()
    if data.phone: current_user.phone = data.phone.strip()
    if data.address: current_user.address = data.address.strip()
    if data.city: current_user.city = data.city.strip()
    db.commit(); db.refresh(current_user)
    return {"success":True,"user":user_dict(current_user)}

@app.post("/api/admin/login")
def admin_login(data: AdminLoginSchema):
    if data.password != ADMIN_PASSWORD: raise HTTPException(401, "Admin şifrəsi yanlışdır")
    return {"success":True,"token":create_admin_token()}

@app.get("/api/admin/stats")
def admin_stats(is_admin: bool = Depends(get_admin), db: Session = Depends(get_db)):
    orders = db.query(Order).all()
    return {"total_orders":db.query(Order).count(),"total_users":db.query(User).count(),
            "total_products":db.query(Product).filter(Product.active==True).count(),
            "total_revenue":sum(o.total_amount for o in orders),
            "pending_orders":db.query(Order).filter(Order.status=="PENDING").count()}

@app.get("/api/admin/products")
def admin_get_products(is_admin: bool = Depends(get_admin), db: Session = Depends(get_db)):
    return [product_dict(p) for p in db.query(Product).order_by(Product.id.desc()).all()]

@app.post("/api/admin/products")
def admin_create_product(data: ProductSchema, is_admin: bool = Depends(get_admin), db: Session = Depends(get_db)):
    p = Product(**data.dict()); db.add(p); db.commit(); db.refresh(p)
    return product_dict(p)

@app.put("/api/admin/products/{pid}")
def admin_update_product(pid: int, data: ProductSchema, is_admin: bool = Depends(get_admin), db: Session = Depends(get_db)):
    p = db.query(Product).filter(Product.id == pid).first()
    if not p: raise HTTPException(404, "Məhsul tapılmadı")
    for k, v in data.dict().items(): setattr(p, k, v)
    db.commit(); db.refresh(p)
    return product_dict(p)

@app.delete("/api/admin/products/{pid}")
def admin_delete_product(pid: int, is_admin: bool = Depends(get_admin), db: Session = Depends(get_db)):
    p = db.query(Product).filter(Product.id == pid).first()
    if not p: raise HTTPException(404, "Məhsul tapılmadı")
    p.active = False; db.commit()
    return {"success":True}

@app.get("/api/admin/orders")
def admin_get_orders(is_admin: bool = Depends(get_admin), db: Session = Depends(get_db)):
    orders = db.query(Order).order_by(Order.created_at.desc()).all()
    return [{"id":o.id,"order_number":o.order_number,"total_amount":o.total_amount,"status":o.status,
             "first_name":o.first_name,"last_name":o.last_name,"phone":o.phone,"email":o.email,
             "address":o.address,"city":o.city,"payment_method":o.payment_method,"note":o.note,
             "created_at":o.created_at.isoformat(),
             "items":[{"name":i.product.name,"emoji":i.product.emoji,"qty":i.quantity,"price":i.unit_price} for i in o.items]}
            for o in orders]

@app.patch("/api/admin/orders/{oid}/status")
def admin_update_order(oid: int, data: OrderStatusSchema, is_admin: bool = Depends(get_admin), db: Session = Depends(get_db)):
    o = db.query(Order).filter(Order.id == oid).first()
    if not o: raise HTTPException(404, "Sifariş tapılmadı")
    o.status = data.status; db.commit()
    return {"success":True,"status":o.status}

@app.get("/api/admin/users")
def admin_get_users(is_admin: bool = Depends(get_admin), db: Session = Depends(get_db)):
    return [{"id":u.id,"name":u.name,"email":u.email,"phone":u.phone,"city":u.city,
             "is_active":u.is_active,"created_at":u.created_at.isoformat(),"order_count":len(u.orders)}
            for u in db.query(User).order_by(User.created_at.desc()).all()]

@app.get("/api/products")
def get_products(category: str = None, search: str = None, db: Session = Depends(get_db)):
    q = db.query(Product).filter(Product.active == True)
    if category and category != "all": q = q.filter(Product.category == category)
    if search: q = q.filter(Product.name.ilike(f"%{search}%"))
    return [product_dict(p) for p in q.all()]

@app.get("/api/products/{pid}")
def get_product(pid: int, db: Session = Depends(get_db)):
    p = db.query(Product).filter(Product.id == pid, Product.active == True).first()
    if not p: raise HTTPException(404, "Məhsul tapılmadı")
    return product_dict(p)

@app.post("/api/orders")
def create_order(data: OrderSchema, current_user: User = Depends(get_user), db: Session = Depends(get_db)):
    count = db.query(Order).count()
    order_number = f"#AURA-{1001 + count}"
    total = 0; pairs = []
    for ci in data.items:
        p = db.query(Product).filter(Product.id == ci.product_id).first()
        if not p: raise HTTPException(404, f"Məhsul tapılmadı: {ci.product_id}")
        if p.stock < ci.quantity: raise HTTPException(400, f"'{p.name}' anbarda yoxdur")
        total += p.price * ci.quantity; pairs.append((p, ci.quantity))
    order = Order(order_number=order_number, user_id=current_user.id, first_name=data.first_name,
                  last_name=data.last_name, phone=data.phone, email=data.email, address=data.address,
                  city=data.city, payment_method=data.payment_method, note=data.note, total_amount=total)
    db.add(order); db.commit(); db.refresh(order)
    for p, qty in pairs:
        db.add(OrderItem(order_id=order.id, product_id=p.id, quantity=qty, unit_price=p.price))
        p.stock -= qty
    db.commit(); db.refresh(order)
    send_email(order)
    return {"success":True,"order_number":order.order_number,"order_id":order.id,
            "total_amount":order.total_amount,"message":"Sifarişiniz qəbul edildi!"}

@app.get("/api/orders/my")
def my_orders(current_user: User = Depends(get_user), db: Session = Depends(get_db)):
    orders = db.query(Order).filter(Order.user_id == current_user.id).order_by(Order.created_at.desc()).all()
    return [{"id":o.id,"order_number":o.order_number,"total_amount":o.total_amount,"status":o.status,
             "city":o.city,"payment_method":o.payment_method,"created_at":o.created_at.isoformat(),
             "items":[{"name":i.product.name,"emoji":i.product.emoji,"qty":i.quantity,"price":i.unit_price} for i in o.items]}
            for o in orders]

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
        db.add_all([Product(name=n,category=c,price=pr,old_price=op,emoji=e,rating=r,review_count=rc,badge=b,stock=s,description=d) for n,c,pr,op,e,r,rc,b,s,d in items])
        db.commit()
        print(f"✅ {len(items)} məhsul əlavə edildi")
    finally:
        db.close()









@app.delete("/delete-test")
def delete_test():
    db = SessionLocal()

    user = db.query(User).filter(
        User.email=="vaqifqasimli023@gmail.com"
    ).first()

    if user:
        db.delete(user)
        db.commit()

    db.close()

    return {"ok": True}
