import { useState } from "react";

import { useToast } from "../../context/ToastContext";

type ProductRow = {
  id: number;
  name: string;
  qty: string;
  unitPrice: string;
  discount: string;
};

const createInvoiceInitialProducts: ProductRow[] = [
  { id: 1, name: "Story Book", qty: "5", unitPrice: "150", discount: "50" },
  {
    id: 2,
    name: "Computer Equipment",
    qty: "1",
    unitPrice: "1030",
    discount: "30",
  },
  {
    id: 3,
    name: "Laptop Servicing",
    qty: "1",
    unitPrice: "270",
    discount: "0",
  },
];

function parseMoney(value: string): number {
  const parsed = parseFloat(String(value).replace(/[^0-9.-]/g, ""));
  return Number.isNaN(parsed) ? 0 : parsed;
}

function formatMoney(value: number): string {
  return (
    "$" +
    (Math.round(value * 100) / 100)
      .toFixed(2)
      .replace(/\B(?=(\d{3})+(?!\d))/g, ",")
  );
}

export default function CreateInvoicesView() {
  const { toast } = useToast();
  const [products, setProducts] = useState<ProductRow[]>(
    createInvoiceInitialProducts,
  );
  const [nextId, setNextId] = useState(4);
  const [notes, setNotes] = useState("");

  const updateRow = (id: number, field: keyof ProductRow, value: string) => {
    setProducts((current) =>
      current.map((row) => (row.id === id ? { ...row, [field]: value } : row)),
    );
  };

  const addProduct = () => {
    setProducts((current) => [
      ...current,
      { id: nextId, name: "", qty: "", unitPrice: "", discount: "" },
    ]);
    setNextId((current) => current + 1);
  };

  const removeRow = (id: number) => {
    if (products.length <= 1) return;
    setProducts((current) => current.filter((row) => row.id !== id));
  };

  const subtotal = products.reduce((sum, row) => {
    const quantity = parseMoney(row.qty);
    const unitPrice = parseMoney(row.unitPrice);
    const discount = parseMoney(row.discount);
    return sum + (quantity * unitPrice - discount);
  }, 0);
  const tax = subtotal * 0.08;
  const grandTotal = subtotal + tax;

  const saveInvoice = () => {
    const payload = {
      products,
      subtotal,
      tax,
      grandTotal,
      notes,
      savedAt: new Date().toISOString(),
    };

    try {
      localStorage.setItem("invoice_draft", JSON.stringify(payload));
      toast("Invoice saved locally (key: invoice_draft)");
    } catch (error) {
      console.error(error);
      toast("Cannot save invoice to localStorage", "error");
    }
  };

  return (
    <section className="create-invoices-section">
      <div className="card create-invoice-card">
        <h3>Buyer Information</h3>
        <div className="form-grid">
          <div className="form-group">
            <label>Name</label>
            <input type="text" defaultValue="Freshbooks" />
          </div>
          <div className="form-group">
            <label>Address</label>
            <input type="text" defaultValue="Los Angeles, California, USA" />
          </div>
          <div className="form-group">
            <label>Email</label>
            <input type="email" defaultValue="freshbooks@mail.com" />
          </div>
          <div className="form-group">
            <label>Phone Number</label>
            <input type="text" defaultValue="444 565 233 889" />
          </div>
          <div className="form-group">
            <label>Due Date</label>
            <input
              type="text"
              defaultValue="25 February, 2021"
              className="with-icon"
            />
          </div>
          <div className="form-group">
            <label>Invoice ID</label>
            <input type="text" defaultValue="#VM056DL8" />
          </div>
        </div>
      </div>
      <div className="card create-invoice-card">
        <h3>Product Information</h3>
        <div className="products-table-wrap">
          <table className="products-table">
            <thead>
              <tr>
                <th>SL No</th>
                <th>Product Name</th>
                <th>Quantity</th>
                <th>Unit Price</th>
                <th>Discount</th>
                <th>Total Price</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {products.map((row, index) => {
                const quantity = parseMoney(row.qty);
                const unitPrice = parseMoney(row.unitPrice);
                const discount = parseMoney(row.discount);
                const total = quantity * unitPrice - discount;

                return (
                  <tr key={row.id}>
                    <td>{index + 1}</td>
                    <td>
                      <input
                        type="text"
                        value={row.name}
                        onChange={(event) =>
                          updateRow(row.id, "name", event.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={row.qty}
                        onChange={(event) =>
                          updateRow(row.id, "qty", event.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={row.unitPrice}
                        onChange={(event) =>
                          updateRow(row.id, "unitPrice", event.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={row.discount}
                        onChange={(event) =>
                          updateRow(row.id, "discount", event.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <span className="cell-total">{formatMoney(total)}</span>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn-remove-row"
                        onClick={() => removeRow(row.id)}
                        title="Remove"
                      >
                        x
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="invoice-grand-total">
          <div className="invoice-summary-row">
            <span>Subtotal</span>
            <strong>{formatMoney(subtotal)}</strong>
          </div>
          <div className="invoice-summary-row">
            <span>Tax (8%)</span>
            <strong>{formatMoney(tax)}</strong>
          </div>
          <div className="invoice-summary-row total">
            <span>Grand Total</span>
            <strong>{formatMoney(grandTotal)}</strong>
          </div>
        </div>
        <textarea
          className="invoice-notes"
          placeholder="Notes for buyer or internal remarks"
          value={notes}
          onChange={(event) => setNotes(event.target.value)}
        />
        <div className="invoice-actions">
          <button
            type="button"
            className="btn-add-product"
            onClick={addProduct}
          >
            + Add Product
          </button>
          <button type="button" className="btn-primary" onClick={saveInvoice}>
            Save Draft
          </button>
        </div>
      </div>
    </section>
  );
}
