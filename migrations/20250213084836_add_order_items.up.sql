CREATE TABLE IF NOT EXISTS order_items (
  "id" uuid PRIMARY KEY NOT NULL DEFAULT (uuid_generate_v4()),
  "order_Id" uuid NOT NULL REFERENCES orders(id),
  "product_Id" uuid NOT NULL REFERENCES products(id),
  "quantity" int NOT NULL,
  "price" decimal(10, 2) NOT NULL
);