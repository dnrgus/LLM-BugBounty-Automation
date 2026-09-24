from fastapi import Depends, FastAPI
from pydantic import BaseModel

app = FastAPI()


class OrderIn(BaseModel):
    item_id: int
    quantity: int


def current_user():
    return {"id": 1}


@app.get("/orders/{order_id}")
def read_order(order_id: int, user=Depends(current_user)):
    return {"order_id": order_id}


@app.post("/orders")
def create_order(order: OrderIn, user=Depends(current_user)):
    return {"item_id": order.item_id}


@app.get("/items")
def list_items(limit: int = 10, category: str = "all"):
    return {"limit": limit, "category": category}
