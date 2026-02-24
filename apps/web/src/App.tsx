import { useState, useEffect, useRef } from "react";

import { useAuth } from "./context/AuthContext";
import { useToast } from "./context/ToastContext";
import "./index.css";

const NAV_ITEMS: {
  id: string;
  label: string;
  children?: { id: string; label: string }[];
}[] = [
  { id: "Dashboard", label: "Dashboard" },
  { id: "My Wallet", label: "My Wallet" },
  { id: "Transactions", label: "Transactions" },
  {
    id: "Invoices",
    label: "Invoices",
    children: [
      { id: "Invoice List", label: "Invoice List" },
      { id: "Create Invoices", label: "Create Invoices" },
    ],
  },
  { id: "Card Center", label: "Card Center" },
  { id: "Accounts", label: "Accounts" },
  { id: "Setting", label: "Setting" },
  {
    id: "Utilities",
    label: "Utilities",
    children: [
      { id: "Knowledge base", label: "Knowledge base" },
      { id: "404", label: "404" },
      { id: "Protected Page", label: "Protected Page" },
      { id: "Changelog", label: "Changelog" },
      { id: "License", label: "License" },
    ],
  },
  {
    id: "Authentication",
    label: "Authentication",
    children: [
      { id: "Sign In", label: "Sign In" },
      { id: "Sign Up", label: "Sign Up" },
    ],
  },
];

const expenseCategories = [
  { label: "Food & Grocery", value: 55 },
  { label: "Transport", value: 40 },
  { label: "Medical", value: 20 },
  { label: "Shopping", value: 30 },
  { label: "Bill & Others", value: 30 },
];

const transactions = [
  {
    icon: "🎁",
    title: "Shopping",
    type: "Payment",
    date: "20 February, 2021",
    time: "10:25 AM",
    amount: "$50.99",
  },
  {
    icon: "🚗",
    title: "Car Repair",
    type: "Payment",
    date: "18 February, 2021",
    time: "03:15 PM",
    amount: "$156.58",
  },
  {
    icon: "🛒",
    title: "Grocery",
    type: "Credit",
    date: "15 February, 2021",
    time: "07:17 PM",
    amount: "$29.55",
  },
  {
    icon: "🏋️",
    title: "Grocery",
    type: "Credit",
    date: "15 February, 2021",
    time: "07:17 PM",
    amount: "$29.55",
  },
];

// My Wallet data
const walletBalance = {
  current: "$150,900.75",
  change: "+$530 (2.5%)",
  income: "$35,450",
  expense: "$12,802",
};
const usageStats = {
  percent: 25,
  segments: [
    { label: "Payoneer", color: "var(--accent)" },
    { label: "Mastercard", color: "var(--accent-2)" },
    { label: "Visa", color: "var(--muted)" },
  ],
};
const invoicesList = [
  { name: "Randi Press", time: "10h ago", amount: "$490", img: 1 },
  { name: "Robert", time: "Friday", amount: "$150", img: 2 },
  { name: "Apple Store", time: "February 10, 2021", amount: "$230", img: 3 },
  { name: "Tatiana", time: "February 9, 2021", amount: "$180", img: 4 },
  { name: "David Watson", time: "February 8, 2021", amount: "$520", img: 5 },
  { name: "Amazon", time: "February 7, 2021", amount: "$95", img: 6 },
];
const debitCreditMonths = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];
const debitCreditData = [12, 19, 8, 24, 18, 30, 22, 28, 15, 20, 25, 32].map(
  (d, i) => ({ debit: d, credit: Math.max(5, 25 - i) }),
);
const paymentHistory = [
  {
    name: "Flaming",
    id: "#SD6455JB",
    date: "February 19, 2021, 10:50 AM",
    amount: "+$1,250",
    method: "Mastercard",
    status: "Completed",
    statusType: "completed",
    img: 7,
  },
  {
    name: "Harold",
    id: "#SD6455JB",
    date: "February 15, 2021, 08:25 PM",
    amount: "-$3,500",
    method: "Paypal",
    status: "Canceled",
    statusType: "canceled",
    img: 8,
  },
  {
    name: "Samuel",
    id: "#SD6455JB",
    date: "February 12, 2021, 02:06 PM",
    amount: "+$800",
    method: "Paypal",
    status: "Pending",
    statusType: "pending",
    img: 9,
  },
  {
    name: "Bernerd",
    id: "#SD6455JB",
    date: "February 19, 2021, 03:14 AM",
    amount: "+$1,800",
    method: "Mastercard",
    status: "Completed",
    statusType: "completed",
    img: 10,
  },
];

const transactionsHistory = [
  {
    id: "596380",
    name: "Charlotte",
    date: "February 19, 2021, 10:50 AM",
    amount: "$590",
    card: "Mastercard",
    status: "Pending",
    statusType: "pending",
    img: 11,
  },
  {
    id: "596381",
    name: "Alexander",
    date: "February 18, 2021, 03:25 PM",
    amount: "$1250",
    card: "Mastercard",
    status: "Pending",
    statusType: "pending",
    img: 12,
  },
  {
    id: "596382",
    name: "Christopher",
    date: "February 18, 2021, 10:12 AM",
    amount: "$5600",
    card: "Paypal",
    status: "Completed",
    statusType: "completed",
    img: 13,
  },
  {
    id: "596383",
    name: "Jonathan",
    date: "February 15, 2021, 09:26 AM",
    amount: "$1260",
    card: "Paypal",
    status: "Completed",
    statusType: "completed",
    img: 14,
  },
  {
    id: "596384",
    name: "Brayden",
    date: "February 15, 2021, 05:37 AM",
    amount: "$3540",
    card: "Mastercard",
    status: "Completed",
    statusType: "completed",
    img: 15,
  },
  {
    id: "596385",
    name: "Nicholas",
    date: "February 15, 2021, 07:46 AM",
    amount: "$750",
    card: "Payoneer",
    status: "Completed",
    statusType: "completed-alt",
    img: 16,
  },
  {
    id: "596386",
    name: "Jeremiah",
    date: "February 10, 2021, 10:50 AM",
    amount: "$240",
    card: "Payoneer",
    status: "Completed",
    statusType: "completed",
    img: 17,
  },
];

function Ring({ value }: { value: number }) {
  const dash = `${value * 2.64} ${264 - value * 2.64}`;
  return (
    <svg viewBox="0 0 84 84" className="ring">
      <circle className="ring-bg" cx="42" cy="42" r="42" />
      <circle
        className="ring-fg"
        cx="42"
        cy="42"
        r="42"
        strokeDasharray={dash}
      />
      <text x="50%" y="52%" textAnchor="middle" className="ring-text">
        {value}%
      </text>
    </svg>
  );
}

function DonutChart({
  percent,
  segments,
}: {
  percent: number;
  segments: { label: string; color: string }[];
}) {
  const r = 42;
  const circ = 2 * Math.PI * r;
  const filled = (percent / 100) * circ;
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 100 100" className="donut-chart">
        <circle className="donut-bg" cx="50" cy="50" r={r} />
        <circle
          className="donut-fg"
          cx="50"
          cy="50"
          r={r}
          strokeDasharray={`${filled} ${circ - filled}`}
        />
        <text x="50" y="55" textAnchor="middle" className="donut-text">
          {percent}%
        </text>
      </svg>
      <div className="donut-legend">
        {segments.map((s) => (
          <div key={s.label} className="donut-legend-item">
            <span className="dot" style={{ background: s.color }} /> {s.label}
          </div>
        ))}
      </div>
    </div>
  );
}

function BarChart({
  labels,
  data,
}: {
  labels: string[];
  data: { debit: number; credit: number }[];
}) {
  const max = Math.max(...data.flatMap((d) => [d.debit, d.credit]));
  return (
    <div className="bar-chart">
      <div className="bar-chart-bars">
        {data.map((d, i) => (
          <div key={i} className="bar-chart-group">
            <div className="bar-wrap">
              <div
                className="bar bar-debit"
                style={{ height: `${(d.debit / max) * 100}%` }}
              />
              <div
                className="bar bar-credit"
                style={{ height: `${(d.credit / max) * 100}%` }}
              />
            </div>
            <span className="bar-label">{labels[i]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DashboardView() {
  return (
    <>
      <section className="grid">
        <div className="card span-2">
          <h3>Expense Categories</h3>
          <div className="rings">
            {expenseCategories.map((c) => (
              <div key={c.label} className="ring-item">
                <Ring value={c.value} />
                <div className="ring-label">{c.label}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="card">
          <div className="profile">
            <img src="https://i.pravatar.cc/120?img=12" alt="John Doe" />
            <h3>John Doe</h3>
            <a href="mailto:hello@zainiklab.com">hello@zainiklab.com</a>
          </div>
          <div className="balance-box">
            <div className="muted">Current Balance</div>
            <div className="big">$340,500</div>
            <div className="mini-stats">
              <div>
                <span className="dot blue" /> Income <strong>$35,450</strong>
              </div>
              <div>
                <span className="dot cyan" /> Expense <strong>$12,802</strong>
              </div>
            </div>
          </div>
          <div className="quick-actions">
            <button>💸 Money Transfer</button>
            <button>🏧 Money Withdrawal</button>
            <button>💳 Make Payment</button>
          </div>
          <div className="card-visual">
            <div className="card-chip" />
            <div className="card-number">1234 5678 9012 3456</div>
            <div className="card-name">John Doe</div>
            <div className="card-valid">12/23</div>
          </div>
        </div>
        <div className="card span-2">
          <div className="card-head">
            <h3>Balance History</h3>
            <div className="legend">
              <span className="dot blue" /> Income
              <span className="dot cyan" /> Balance
              <span className="chevron">▼</span>
            </div>
          </div>
          <div className="chart-placeholder">
            <div className="bar-line" />
          </div>
        </div>
        <div className="card span-2">
          <div className="card-head">
            <h3>Last Transactions</h3>
            <button className="pill">All Time ▼</button>
          </div>
          <div className="txn-list">
            {transactions.map((t, i) => (
              <div key={i} className="txn-row">
                <span className="txn-icon">{t.icon}</span>
                <span>{t.title}</span>
                <span className="muted">{t.type}</span>
                <span className="muted">{t.date}</span>
                <span className="muted">{t.time}</span>
                <span>{t.amount}</span>
                <span className="muted">⋮</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}

function MyWalletView() {
  return (
    <>
      <section className="grid grid-wallet">
        <div className="card wallet-balance-card">
          <h3>Wallet Balance</h3>
          <div className="wallet-balance-big">{walletBalance.current}</div>
          <div className="wallet-balance-change">▲{walletBalance.change}</div>
          <div className="wallet-mini-stats">
            <div>
              <span className="dot blue" /> Income{" "}
              <strong>{walletBalance.income}</strong>
            </div>
            <div>
              <span className="dot cyan" /> Expense{" "}
              <strong>{walletBalance.expense}</strong>
            </div>
          </div>
        </div>
        <div className="card usage-card">
          <h3>Usage Statistics</h3>
          <DonutChart
            percent={usageStats.percent}
            segments={usageStats.segments}
          />
        </div>
        <div className="card invoices-card">
          <h3>Invoices List</h3>
          <div className="invoices-list">
            {invoicesList.map((inv) => (
              <div key={inv.name} className="invoice-row">
                <img
                  src={`https://i.pravatar.cc/40?img=${inv.img}`}
                  alt=""
                  className="invoice-avatar"
                />
                <div className="invoice-info">
                  <span className="invoice-name">{inv.name}</span>
                  <span className="invoice-time muted">{inv.time}</span>
                </div>
                <span className="invoice-amount">{inv.amount}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="card span-2 debit-credit-card">
          <div className="card-head">
            <h3>Debit & Credit History</h3>
            <div className="legend">
              <span className="dot blue" /> Debit
              <span className="dot cyan" /> Credit
            </div>
          </div>
          <div className="history-tabs">
            <button className="history-tab active">Monthly</button>
            <button className="history-tab">Weekly</button>
            <button className="history-tab">All Time</button>
          </div>
          <div className="chart-placeholder chart-bars">
            <BarChart labels={debitCreditMonths} data={debitCreditData} />
          </div>
        </div>
        <div className="card span-2 payment-history-card">
          <div className="card-head">
            <h3>Payment History</h3>
            <button className="pill">This Week ▼</button>
          </div>
          <div className="payment-history-list">
            {paymentHistory.map((p) => (
              <div key={p.name + p.date} className="payment-row">
                <img
                  src={`https://i.pravatar.cc/48?img=${p.img}`}
                  alt=""
                  className="payment-avatar"
                />
                <div className="payment-user">
                  <span className="payment-name">{p.name}</span>
                  <span className="muted payment-id">{p.id}</span>
                </div>
                <span className="muted payment-date">{p.date}</span>
                <span
                  className={`payment-amount ${p.amount.startsWith("+") ? "positive" : "negative"}`}
                >
                  {p.amount}
                </span>
                <span className="muted payment-method">{p.method}</span>
                <span className={`status-badge status-${p.statusType}`}>
                  {p.status}
                </span>
                <span className="payment-dots">⋮</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}

// Invoice list for Invoice List tab (full list view)
const invoiceListData = [
  {
    id: "#VM056DL8",
    name: "Freshbooks",
    date: "25 February, 2021",
    amount: "$1,970",
    status: "Paid",
    statusType: "completed",
    img: 20,
  },
  {
    id: "#VM056DL7",
    name: "Randi Press",
    date: "24 February, 2021",
    amount: "$490",
    status: "Pending",
    statusType: "pending",
    img: 1,
  },
  {
    id: "#VM056DL6",
    name: "Apple Store",
    date: "10 February, 2021",
    amount: "$230",
    status: "Paid",
    statusType: "completed",
    img: 3,
  },
  {
    id: "#VM056DL5",
    name: "Amazon",
    date: "7 February, 2021",
    amount: "$95",
    status: "Overdue",
    statusType: "canceled",
    img: 6,
  },
];

function InvoiceListView() {
  return (
    <section className="invoice-list-section">
      <div className="card invoice-list-card">
        <h3>Invoice List</h3>
        <div className="invoice-list-table-wrap">
          <table className="transactions-table invoice-list-table">
            <thead>
              <tr>
                <th>Invoice ID</th>
                <th>Client</th>
                <th>Due Date</th>
                <th>Amount</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {invoiceListData.map((inv) => (
                <tr key={inv.id + inv.date}>
                  <td className="tx-id">{inv.id}</td>
                  <td>
                    <div className="tx-recipient">
                      <img
                        src={`https://i.pravatar.cc/40?img=${inv.img}`}
                        alt=""
                        className="tx-recipient-avatar"
                      />
                      <span>{inv.name}</span>
                    </div>
                  </td>
                  <td className="muted">{inv.date}</td>
                  <td className="tx-amount">{inv.amount}</td>
                  <td>
                    <span className={`status-badge status-${inv.statusType}`}>
                      {inv.status}
                    </span>
                  </td>
                  <td>
                    <span className="tx-dots">⋮</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function parseMoney(s: string): number {
  const n = parseFloat(String(s).replace(/[^0-9.-]/g, ""));
  return isNaN(n) ? 0 : n;
}
function formatMoney(n: number): string {
  return (
    "$" +
    (Math.round(n * 100) / 100).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ",")
  );
}

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

function CreateInvoicesView() {
  const [products, setProducts] = useState<ProductRow[]>(
    createInvoiceInitialProducts,
  );
  const [nextId, setNextId] = useState(4);

  const updateRow = (id: number, field: keyof ProductRow, value: string) => {
    setProducts((p) =>
      p.map((r) => (r.id === id ? { ...r, [field]: value } : r)),
    );
  };

  const addProduct = () => {
    setProducts((p) => [
      ...p,
      { id: nextId, name: "", qty: "", unitPrice: "", discount: "" },
    ]);
    setNextId((n) => n + 1);
  };

  const removeRow = (id: number) => {
    if (products.length <= 1) return;
    setProducts((p) => p.filter((r) => r.id !== id));
  };

  const grandTotal = products.reduce((sum, r) => {
    const q = parseMoney(r.qty);
    const u = parseMoney(r.unitPrice);
    const d = parseMoney(r.discount);
    return sum + (q * u - d);
  }, 0);

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
              {products.map((row, i) => {
                const q = parseMoney(row.qty);
                const u = parseMoney(row.unitPrice);
                const d = parseMoney(row.discount);
                const total = q * u - d;
                return (
                  <tr key={row.id}>
                    <td>{i + 1}</td>
                    <td>
                      <input
                        type="text"
                        value={row.name}
                        onChange={(e) =>
                          updateRow(row.id, "name", e.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={row.qty}
                        onChange={(e) =>
                          updateRow(row.id, "qty", e.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={row.unitPrice}
                        onChange={(e) =>
                          updateRow(row.id, "unitPrice", e.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={row.discount}
                        onChange={(e) =>
                          updateRow(row.id, "discount", e.target.value)
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
                        ✕
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="invoice-grand-total">
          Grand Total: <strong>{formatMoney(grandTotal)}</strong>
        </div>
        <button type="button" className="btn-add-product" onClick={addProduct}>
          + Add Product
        </button>
      </div>
    </section>
  );
}

const initialCardList = [
  {
    id: 1,
    type: "Mastercard",
    status: "Primary",
    bank: "DBL Bank",
    number: "3778 4545 9685****",
    holder: "William",
    img: 1,
  },
  {
    id: 2,
    type: "Skrill",
    status: "",
    bank: "Skrill Inc.",
    number: "3778 4545 9685****",
    holder: "William",
    img: 2,
  },
];
const recentTransfers = [
  {
    name: "Randi Press",
    date: "February 20, 2021",
    amount: "-$490",
    positive: false,
    img: 1,
  },
  {
    name: "David Bekam",
    date: "February 19, 2021",
    amount: "+$250",
    positive: true,
    img: 2,
  },
  {
    name: "Spotify",
    date: "February 19, 2021",
    amount: "-$15",
    positive: false,
    img: 3,
  },
];

function CardCenterView() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [cardList, setCardList] = useState(initialCardList);
  const [addCardOpen, setAddCardOpen] = useState(false);
  const [newCard, setNewCard] = useState({
    type: "Mastercard",
    bank: "",
    number: "",
    holder: user?.name ?? "John Doe",
  });

  const addCard = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCard.number.trim() || !newCard.bank.trim()) {
      toast("Please fill card number and bank", "error");
      return;
    }
    const digits = newCard.number.replace(/\D/g, "").slice(-4);
    const masked =
      "**** **** **** " +
      (digits.length >= 4 ? digits : digits.padStart(4, "*"));
    setCardList((p) => [
      ...p,
      {
        id: Date.now(),
        type: newCard.type,
        status: p.length === 0 ? "Primary" : "",
        bank: newCard.bank,
        number: masked,
        holder: newCard.holder,
        img: (p.length % 10) + 1,
      },
    ]);
    setNewCard({
      type: "Mastercard",
      bank: "",
      number: "",
      holder: user?.name ?? "John Doe",
    });
    setAddCardOpen(false);
    toast("Card added successfully");
  };

  return (
    <section className="grid grid-card-center">
      <div className="card my-cards-card">
        <div className="card-head">
          <h3>My Cards</h3>
          <button
            type="button"
            className="link-add"
            onClick={() => setAddCardOpen(true)}
          >
            Add Card
          </button>
        </div>
        <div className="my-cards-stack">
          {cardList.slice(0, 2).map((c) => (
            <div key={c.id} className="card-visual mini">
              <div className="card-chip" />
              <div className="card-number">{c.number}</div>
              <div className="card-name">{c.holder}</div>
              <div className="card-valid">12/23</div>
              <div className="card-brand">
                {c.type} · {c.bank}
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="card current-balance-card">
        <h3>Current Balance</h3>
        <div className="balance-value">$340,500</div>
        <div className="mini-bars">
          {[40, 65, 45, 80, 55, 70, 50, 90].map((h, i) => (
            <div key={i} className="mini-bar" style={{ height: `${h}%` }} />
          ))}
        </div>
      </div>
      <div className="card payment-method-card">
        <h3>Payment Method</h3>
        <div className="method-tabs">
          <button type="button" className="method-tab active">
            Payoneer
          </button>
          <button type="button" className="method-tab">
            Mastercard
          </button>
          <button type="button" className="method-tab">
            Visa
          </button>
        </div>
        <div className="period-tabs">
          <button type="button" className="period-tab active">
            Monthly
          </button>
          <button type="button" className="period-tab">
            Weekly
          </button>
        </div>
        <div className="line-chart-placeholder" />
      </div>
      <div className="card card-expenses-card">
        <h3>Card Expenses</h3>
        <DonutChart
          percent={45}
          segments={[
            { label: "Mastercard 30%", color: "var(--accent)" },
            { label: "Payoneer 25%", color: "var(--accent-2)" },
            { label: "Visa 45%", color: "#1a3a5c" },
          ]}
        />
      </div>
      <div className="card card-list-card span-2">
        <h3>Card List</h3>
        <div className="transactions-table-wrap">
          <table className="transactions-table">
            <thead>
              <tr>
                <th>Card Type</th>
                <th>Status</th>
                <th>Bank</th>
                <th>Card Number</th>
                <th>Card Holder</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {cardList.map((c) => (
                <tr key={c.id}>
                  <td>{c.type}</td>
                  <td>
                    {c.status ? (
                      <span className="status-badge status-completed">
                        {c.status}
                      </span>
                    ) : (
                      ""
                    )}
                  </td>
                  <td className="muted">{c.bank}</td>
                  <td>{c.number}</td>
                  <td>{c.holder}</td>
                  <td>
                    <span className="tx-dots">⋮</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {addCardOpen && (
        <div className="modal-overlay" onClick={() => setAddCardOpen(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <h3>Add Card</h3>
            <form onSubmit={addCard}>
              <div className="form-group">
                <label>Card Type</label>
                <select
                  value={newCard.type}
                  onChange={(e) =>
                    setNewCard((p) => ({ ...p, type: e.target.value }))
                  }
                >
                  <option value="Mastercard">Mastercard</option>
                  <option value="Visa">Visa</option>
                  <option value="Skrill">Skrill</option>
                </select>
              </div>
              <div className="form-group">
                <label>Bank</label>
                <input
                  type="text"
                  value={newCard.bank}
                  onChange={(e) =>
                    setNewCard((p) => ({ ...p, bank: e.target.value }))
                  }
                  placeholder="Bank name"
                  required
                />
              </div>
              <div className="form-group">
                <label>Card Number</label>
                <input
                  type="text"
                  value={newCard.number}
                  onChange={(e) =>
                    setNewCard((p) => ({ ...p, number: e.target.value }))
                  }
                  placeholder="1234 5678 9012 3456"
                  required
                />
              </div>
              <div className="form-group">
                <label>Card Holder</label>
                <input
                  type="text"
                  value={newCard.holder}
                  onChange={(e) =>
                    setNewCard((p) => ({ ...p, holder: e.target.value }))
                  }
                />
              </div>
              <div className="modal-actions">
                <button
                  type="button"
                  className="pill"
                  onClick={() => setAddCardOpen(false)}
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  Add Card
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      <div className="card recent-transfer-card">
        <h3>Recent Transfer</h3>
        <div className="recent-transfer-list">
          {recentTransfers.map((t, i) => (
            <div key={i} className="recent-transfer-row">
              <img
                src={`https://i.pravatar.cc/40?img=${t.img}`}
                alt=""
                className="tx-recipient-avatar"
              />
              <div className="recent-transfer-info">
                <span>{t.name}</span>
                <span className="muted">{t.date}</span>
              </div>
              <span
                className={`recent-transfer-amount ${t.positive ? "positive" : "negative"}`}
              >
                {t.amount}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function AccountsView() {
  return (
    <section className="grid grid-accounts">
      <div className="card invest-card">
        <div className="invest-content">
          <h3>Invest your money for a better future</h3>
          <p className="muted">
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut eu
            feugiat amet.
          </p>
          <button type="button" className="btn-primary">
            Invest Now
          </button>
        </div>
        <div className="invest-illus">💰</div>
      </div>
      <div className="card profile-summary-card">
        <div className="profile-summary">
          <img src="https://i.pravatar.cc/80?img=12" alt="" />
          <h3>John Doe</h3>
          <p className="muted">UI/UX Designer</p>
          <p className="muted">Los Angeles, USA</p>
        </div>
        <div className="profile-stats">
          <div className="stat-circle">
            <span className="stat-label">Income</span>
            <strong>$35,450</strong>
          </div>
          <div className="stat-circle">
            <span className="stat-label">Expense</span>
            <strong>$12,800</strong>
          </div>
        </div>
        <div className="profile-mycard">
          <span className="muted">My Card</span>
          <strong>4 Cards Available</strong>
          <div className="card-visual mini">
            <div className="card-chip" />
            <div className="card-number">1234 5678 9012 3456</div>
            <div className="card-name">John Doe</div>
            <div className="card-valid">12/23</div>
            <div className="card-brand">Bank Asia</div>
          </div>
        </div>
      </div>
      <div className="card span-2">
        <div className="card-head">
          <h3>Last Transactions</h3>
          <button className="pill">All Time ▼</button>
        </div>
        <div className="txn-list">
          {transactions.map((t, i) => (
            <div key={i} className="txn-row">
              <span className="txn-icon">{t.icon}</span>
              <span>{t.title}</span>
              <span className="muted">{t.type}</span>
              <span className="muted">{t.date}</span>
              <span className="muted">{t.time}</span>
              <span>{t.amount}</span>
              <span className="muted">⋮</span>
            </div>
          ))}
        </div>
      </div>
      <div className="card quick-transfer-card">
        <h3>Quick Transfer</h3>
        <div className="form-group">
          <label>Choose Your Card</label>
          <input
            type="text"
            defaultValue="3778 4545 9685 1234"
            readOnly
            className="readonly"
          />
        </div>
        <div className="form-group">
          <label>Receiver</label>
          <input type="text" placeholder="Enter receiver card number" />
        </div>
        <div className="form-group">
          <label>Amount</label>
          <input type="text" placeholder="Choose amount" />
        </div>
      </div>
      <div className="card revenue-card">
        <div className="card-head">
          <h3>Revenue</h3>
          <span className="revenue-period">This Month $2,600</span>
        </div>
        <div className="history-tabs">
          <button type="button" className="history-tab active">
            Monthly
          </button>
          <button type="button" className="history-tab">
            Weekly
          </button>
          <button type="button" className="history-tab">
            All Time
          </button>
        </div>
        <div className="chart-placeholder chart-bars">
          <BarChart
            labels={["Jan", "Feb", "Mar", "Apr", "May", "Jun"]}
            data={[
              { debit: 20, credit: 15 },
              { debit: 35, credit: 28 },
              { debit: 25, credit: 22 },
              { debit: 40, credit: 35 },
              { debit: 30, credit: 25 },
              { debit: 45, credit: 38 },
            ]}
          />
        </div>
      </div>
    </section>
  );
}

const SETTING_PROFILE_KEY = "moneyfarm_profile";
type ProfileForm = {
  name: string;
  userName: string;
  email: string;
  password: string;
  dateOfBirth: string;
  presentAddress: string;
  permanentAddress: string;
  postalCode: string;
};
const defaultProfile: ProfileForm = {
  name: "John Doe",
  userName: "johndoe",
  email: "johndoe@mail.com",
  password: "**********",
  dateOfBirth: "25 January, 1990",
  presentAddress: "San Jose, California, USA",
  permanentAddress: "San Jose, California, USA",
  postalCode: "45962",
};

const settingMenuItems = [
  {
    id: "profile",
    label: "My Profile",
    desc: "Details about my personal information.",
    icon: "👤",
    active: true,
  },
  {
    id: "preferences",
    label: "Preferences",
    desc: "Dark and light mode, Font size.",
    icon: "❤",
    active: false,
  },
  {
    id: "security",
    label: "Security",
    desc: "Change password, Authentication.",
    icon: "🔒",
    active: false,
  },
  {
    id: "notification",
    label: "Notification",
    desc: "Change password, Authentication.",
    icon: "🔔",
    active: false,
  },
];

function Toggle({
  checked,
  onChange,
  id,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  id?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      id={id}
      className={`setting-toggle ${checked ? "on" : ""}`}
      onClick={() => onChange(!checked)}
    >
      <span className="setting-toggle-thumb" />
    </button>
  );
}

function SettingView() {
  const { toast } = useToast();
  const [settingTab, setSettingTab] = useState("profile");
  const [profile, setProfile] = useState<ProfileForm>(() => {
    try {
      const s = localStorage.getItem(SETTING_PROFILE_KEY);
      return s ? { ...defaultProfile, ...JSON.parse(s) } : defaultProfile;
    } catch {
      return defaultProfile;
    }
  });
  const [prefStartPage, setPrefStartPage] = useState(false);
  const [prefContinue, setPrefContinue] = useState(false);
  const [prefSpecificPage, setPrefSpecificPage] = useState(true);
  const [prefBlockAds, setPrefBlockAds] = useState(true);
  const [notifLogin, setNotifLogin] = useState(true);
  const [notifDeposit, setNotifDeposit] = useState(false);
  const [notifWithdraw1, setNotifWithdraw1] = useState(true);
  const [notifWithdraw2, setNotifWithdraw2] = useState(true);

  const saveProfile = () => {
    localStorage.setItem(SETTING_PROFILE_KEY, JSON.stringify(profile));
    toast("Profile saved successfully");
  };

  return (
    <section className="setting-section">
      <div className="card setting-menu-card">
        <h3 className="sr-only">Settings</h3>
        {settingMenuItems.map((item) => (
          <div
            key={item.id}
            className={`setting-menu-item ${settingTab === item.id ? "active" : ""}`}
            onClick={() => setSettingTab(item.id)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === "Enter" && setSettingTab(item.id)}
          >
            <span className="setting-menu-icon">{item.icon}</span>
            <div>
              <strong>{item.label}</strong>
              <p className="muted">{item.desc}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="card setting-detail-card">
        {settingTab === "profile" && (
          <>
            <div className="setting-profile-header">
              <div className="setting-avatar-wrap">
                <img
                  src="https://i.pravatar.cc/120?img=12"
                  alt=""
                  className="setting-avatar"
                />
                <span className="setting-avatar-edit">📷</span>
              </div>
            </div>
            <div className="form-grid setting-form">
              <div className="form-group">
                <label>Name</label>
                <input
                  type="text"
                  value={profile.name}
                  onChange={(e) =>
                    setProfile((p) => ({ ...p, name: e.target.value }))
                  }
                />
              </div>
              <div className="form-group">
                <label>User Name</label>
                <input
                  type="text"
                  value={profile.userName}
                  onChange={(e) =>
                    setProfile((p) => ({ ...p, userName: e.target.value }))
                  }
                />
              </div>
              <div className="form-group">
                <label>Email</label>
                <input
                  type="email"
                  value={profile.email}
                  onChange={(e) =>
                    setProfile((p) => ({ ...p, email: e.target.value }))
                  }
                />
              </div>
              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  value={profile.password}
                  onChange={(e) =>
                    setProfile((p) => ({ ...p, password: e.target.value }))
                  }
                />
              </div>
              <div className="form-group">
                <label>Date of Birth</label>
                <input
                  type="text"
                  value={profile.dateOfBirth}
                  onChange={(e) =>
                    setProfile((p) => ({ ...p, dateOfBirth: e.target.value }))
                  }
                />
              </div>
              <div className="form-group">
                <label>Present Address</label>
                <input
                  type="text"
                  value={profile.presentAddress}
                  onChange={(e) =>
                    setProfile((p) => ({
                      ...p,
                      presentAddress: e.target.value,
                    }))
                  }
                />
              </div>
              <div className="form-group">
                <label>Permanent Address</label>
                <input
                  type="text"
                  value={profile.permanentAddress}
                  onChange={(e) =>
                    setProfile((p) => ({
                      ...p,
                      permanentAddress: e.target.value,
                    }))
                  }
                />
              </div>
              <div className="form-group">
                <label>Postal Code</label>
                <input
                  type="text"
                  value={profile.postalCode}
                  onChange={(e) =>
                    setProfile((p) => ({ ...p, postalCode: e.target.value }))
                  }
                />
              </div>
            </div>
            <div className="setting-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={saveProfile}
              >
                Save Changes
              </button>
            </div>
          </>
        )}
        {settingTab === "preferences" && (
          <>
            <h3 className="setting-panel-title">Preference Setting</h3>
            <div className="setting-block">
              <h4 className="setting-block-head">On Startup</h4>
              <div className="setting-row toggle-row">
                <label htmlFor="pref-start">Open the start page</label>
                <Toggle
                  id="pref-start"
                  checked={prefStartPage}
                  onChange={setPrefStartPage}
                />
              </div>
              <div className="setting-row toggle-row">
                <label htmlFor="pref-continue">Continue where I left off</label>
                <Toggle
                  id="pref-continue"
                  checked={prefContinue}
                  onChange={setPrefContinue}
                />
              </div>
              <div className="setting-row toggle-row">
                <label htmlFor="pref-specific">
                  Open a specific page or set of pages
                </label>
                <Toggle
                  id="pref-specific"
                  checked={prefSpecificPage}
                  onChange={setPrefSpecificPage}
                />
              </div>
            </div>
            <div className="setting-block">
              <h4 className="setting-block-head">Block Ads</h4>
              <p className="setting-block-desc muted">
                Block ads and surf the web up to three times faster.
              </p>
              <div className="setting-row toggle-row">
                <span>Enable block ads</span>
                <Toggle checked={prefBlockAds} onChange={setPrefBlockAds} />
              </div>
            </div>
          </>
        )}
        {settingTab === "security" && (
          <>
            <h3 className="setting-panel-title">Security</h3>
            <div className="setting-block">
              <h4 className="setting-block-head">Two-Factor Authentication</h4>
              <div className="setting-item-row">
                <div>
                  <strong>Use two-factor authentication</strong>
                  <p className="muted">
                    We'll ask for a code if we notice an attempted login from an
                    unrecognized device or browser.
                  </p>
                </div>
                <button type="button" className="btn-setting-action">
                  Edit
                </button>
              </div>
              <div className="setting-item-row">
                <div>
                  <strong>Authorized Logins</strong>
                  <p className="muted">
                    Review a list of devices where you won't have to use a login
                    code.
                  </p>
                </div>
                <button type="button" className="btn-setting-action">
                  View
                </button>
              </div>
              <div className="setting-item-row">
                <div>
                  <strong>Authorized Logins</strong>
                  <p className="muted">
                    Review a list of devices where you won't have to use a login
                    code.
                  </p>
                </div>
                <button type="button" className="btn-setting-action">
                  View
                </button>
              </div>
            </div>
            <div className="setting-block">
              <h4 className="setting-block-head">Change Password</h4>
              <div className="setting-item-row">
                <div>
                  <strong>Change Password</strong>
                  <p className="muted">
                    Review a list of devices where you won't have to use a login
                    code.
                  </p>
                </div>
                <button type="button" className="btn-setting-action">
                  Edit
                </button>
              </div>
            </div>
            <div className="setting-block">
              <h4 className="setting-block-head">Save Your Login Info</h4>
              <div className="setting-item-row">
                <div>
                  <strong>Save Your Login Info</strong>
                  <p className="muted">
                    It will only be saved on the browsers and devices you
                    choose.
                  </p>
                </div>
                <button type="button" className="btn-setting-action">
                  Edit
                </button>
              </div>
            </div>
          </>
        )}
        {settingTab === "notification" && (
          <>
            <h3 className="setting-panel-title">General Notification</h3>
            <div className="setting-block">
              <div className="setting-row toggle-row">
                <label htmlFor="notif-login">
                  Show notification when someone login to my account
                </label>
                <Toggle
                  id="notif-login"
                  checked={notifLogin}
                  onChange={setNotifLogin}
                />
              </div>
              <div className="setting-row toggle-row">
                <label htmlFor="notif-deposit">
                  Show notification when depositing from another account
                </label>
                <Toggle
                  id="notif-deposit"
                  checked={notifDeposit}
                  onChange={setNotifDeposit}
                />
              </div>
              <div className="setting-row toggle-row">
                <label htmlFor="notif-withdraw1">
                  Notify me when withdrawal money from my account
                </label>
                <Toggle
                  id="notif-withdraw1"
                  checked={notifWithdraw1}
                  onChange={setNotifWithdraw1}
                />
              </div>
              <div className="setting-row toggle-row">
                <label htmlFor="notif-withdraw2">
                  Notify me when withdrawal money from my account
                </label>
                <Toggle
                  id="notif-withdraw2"
                  checked={notifWithdraw2}
                  onChange={setNotifWithdraw2}
                />
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
}

// --- Utilities: FAQ (Knowledge base) ---
const faqGeneral = [
  {
    q: "Can I use Master card for shopping?",
    detail:
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut eu feugiat amet.",
  },
  { q: "Have any loan product for women entrepreneurs?" },
  { q: "Who are eligible for availing SME loan?" },
  { q: "What is the maximum amount of SME loan?" },
];
const faqOthers = [
  { q: "What tenor is offered for SME loan?" },
  { q: "What is the early settlement fee?" },
  { q: "What is the partial settlement fee?" },
  { q: "Is there any insurance policy required to avail this loan?" },
];

function KnowledgeBaseView() {
  const [openGeneral, setOpenGeneral] = useState<number | null>(null);
  const [openOthers, setOpenOthers] = useState<number | null>(null);
  return (
    <section className="utility-faq-section">
      <div className="card faq-card">
        <h3>General Inquires</h3>
        <ul className="faq-list">
          {faqGeneral.map((item, i) => (
            <li key={i} className="faq-item">
              <div
                className="faq-item-inner"
                onClick={() => setOpenGeneral(openGeneral === i ? null : i)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) =>
                  e.key === "Enter" &&
                  setOpenGeneral(openGeneral === i ? null : i)
                }
              >
                <span className="faq-q">{item.q}</span>
                <span className="faq-info-icon">
                  {openGeneral === i ? "−" : "ⓘ"}
                </span>
              </div>
              {(item.detail || openGeneral === i) && (
                <p className="muted faq-detail">
                  {item.detail || "No additional details."}
                </p>
              )}
            </li>
          ))}
        </ul>
      </div>
      <div className="card faq-card">
        <h3>Others Informations</h3>
        <ul className="faq-list">
          {faqOthers.map((item, i) => (
            <li key={i} className="faq-item">
              <div
                className="faq-item-inner"
                onClick={() => setOpenOthers(openOthers === i ? null : i)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) =>
                  e.key === "Enter" &&
                  setOpenOthers(openOthers === i ? null : i)
                }
              >
                <span className="faq-q">{item.q}</span>
                <span className="faq-info-icon">
                  {openOthers === i ? "−" : "ⓘ"}
                </span>
              </div>
              {openOthers === i && (
                <p className="muted faq-detail">No additional details.</p>
              )}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

function Error404View({ onGoHome }: { onGoHome?: () => void }) {
  return (
    <section className="utility-404-section">
      <div className="error-404-content">
        <div className="error-404-number">
          <span>4</span>
          <span className="error-404-char">🥔</span>
          <span>4</span>
        </div>
        <h2 className="error-404-title">Page not Found</h2>
        <p className="muted error-404-desc">
          It looks like that page does not exist. Please check the URL and try
          again.
        </p>
        <button type="button" className="btn-primary" onClick={onGoHome}>
          Go Home
        </button>
      </div>
    </section>
  );
}

const PROTECTED_PASSWORD = "1234";

function ProtectedPageView() {
  const [password, setPassword] = useState("");
  const [unlocked, setUnlocked] = useState(false);
  const { toast } = useToast();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (password === PROTECTED_PASSWORD) {
      setUnlocked(true);
      toast("Access granted. Page unlocked.");
    } else {
      toast("Incorrect password. Try 1234 for demo.", "error");
    }
  };

  if (unlocked) {
    return (
      <section className="utility-protected-section">
        <div className="card utility-protected-card">
          <div className="protected-icon">✅</div>
          <h3 className="protected-title">Access Granted</h3>
          <p className="muted protected-desc">
            This page is now unlocked. You have successfully entered the correct
            password.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="utility-protected-section">
      <div className="card utility-protected-card">
        <div className="protected-icon">🔒</div>
        <h3 className="protected-title">Protected Password</h3>
        <p className="muted protected-desc">
          majority have suffered alteration in some form, by injected humour, or
          randomised words which don't look even slightly believable. If you are
          going to use a passage of Lorem Ipsum, you need to be sure there isn't
          anything embarrassing hidden in the middle of text.
        </p>
        <form className="protected-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password (demo: 1234)"
            />
          </div>
          <button type="submit" className="btn-primary">
            Submit
          </button>
        </form>
      </div>
    </section>
  );
}

function ChangelogView() {
  return (
    <section className="utility-changelog-section">
      <div className="card changelog-card">
        <h3 className="changelog-version">Version 1</h3>
        <p className="changelog-subtitle">Dash Release v1.0</p>
        <p className="muted changelog-desc">
          03-11-2022 - Updated visuals & overall design improvements.
        </p>
      </div>
    </section>
  );
}

function LicenseView() {
  return (
    <section className="utility-license-section">
      <div className="card license-card">
        <h3>Icons</h3>
        <p className="muted license-sub">All icon used from Flaticon</p>
        <div className="license-icon-row">
          {["🏢", "📄", "🏛", "💳", "👤", "⚙", "✱"].map((icon, i) => (
            <button key={i} type="button" className="license-icon-btn">
              {icon}
            </button>
          ))}
        </div>
        <button type="button" className="btn-primary license-btn">
          License
        </button>
      </div>
      <div className="card license-card">
        <h3>Typography</h3>
        <p className="muted license-typo">
          accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium
          voluptatum deleniti atque corrupti quos dolores et quas molestias
          excepturi sint occaecati cupiditate non provident, similique sunt in
          culpa qui officia deserunt mollitia animi, id est laborum et dolorum
          fuga. Et harum quidem rerum facilis est et expedita distinctio. Nam
          libero tempore, cum soluta nobis est eligendi optio cumque nihil
          impedit quo minus id quod
        </p>
        <button type="button" className="btn-primary license-btn">
          License
        </button>
      </div>
    </section>
  );
}

const AUTH_LOREM =
  "It is a long established fact that a reader will be distracted by the readable content of a page when looking at its layout. The point of using Lorem Ipsum is that it has.";

function AuthPanel() {
  return (
    <div className="auth-illust-panel">
      <div className="auth-illust">🪙</div>
      <div className="auth-brand">F MoneyFarm</div>
      <p className="muted auth-panel-desc">{AUTH_LOREM}</p>
    </div>
  );
}

function SignInView({
  onNavigateSignUp,
  onSignInSuccess,
}: {
  onNavigateSignUp: () => void;
  onSignInSuccess?: () => void;
}) {
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const { login } = useAuth();
  const { toast } = useToast();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) {
      toast("Please enter email", "error");
      return;
    }
    if (!password) {
      toast("Please enter password", "error");
      return;
    }
    login(email, password);
    toast("Signed in successfully");
    onSignInSuccess?.();
  };

  return (
    <section className="auth-section">
      <div className="auth-card">
        <h2 className="auth-title">Sign In</h2>
        <p className="muted auth-intro">{AUTH_LOREM}</p>
        <div className="auth-social-row">
          <button type="button" className="auth-social-btn">
            <span className="auth-social-icon g">G</span> Sign In With Google
          </button>
          <button type="button" className="auth-social-btn">
            <span className="auth-social-icon f">f</span> Sign In With Facebook
          </button>
        </div>
        <div className="auth-sep">
          <span>OR</span>
        </div>
        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="johndoe.banking@gmail.com"
            />
          </div>
          <div className="form-group auth-password-wrap">
            <label>Password</label>
            <div className="auth-password-input">
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="********"
              />
              <button
                type="button"
                className="auth-eye"
                onClick={() => setShowPassword(!showPassword)}
                aria-label="Toggle password"
              >
                {showPassword ? "🙈" : "👁"}
              </button>
            </div>
          </div>
          <div className="auth-options">
            <label className="auth-checkbox">
              <input type="checkbox" /> Remember me
            </label>
            <a
              href="#"
              className="auth-link"
              onClick={(e) => e.preventDefault()}
            >
              Forgot password
            </a>
          </div>
          <button type="submit" className="btn-primary auth-submit">
            Sign In
          </button>
        </form>
        <p className="auth-switch">
          Don't have an account?{" "}
          <button
            type="button"
            className="auth-link-btn"
            onClick={onNavigateSignUp}
          >
            Sign Up
          </button>
        </p>
      </div>
      <AuthPanel />
    </section>
  );
}

function SignUpView({
  onNavigateSignIn,
  onSignUpSuccess,
}: {
  onNavigateSignIn: () => void;
  onSignUpSuccess?: () => void;
}) {
  const [showPassword, setShowPassword] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [agree, setAgree] = useState(false);
  const { signUp } = useAuth();
  const { toast } = useToast();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      toast("Please enter username", "error");
      return;
    }
    if (!email.trim()) {
      toast("Please enter email", "error");
      return;
    }
    if (!password) {
      toast("Please enter password", "error");
      return;
    }
    if (!agree) {
      toast("Please agree to terms & conditions", "error");
      return;
    }
    signUp(name, email, password);
    toast("Account created successfully");
    onSignUpSuccess?.();
  };

  return (
    <section className="auth-section">
      <div className="auth-card">
        <h2 className="auth-title">Sign Up</h2>
        <p className="muted auth-intro">{AUTH_LOREM}</p>
        <div className="auth-social-row">
          <button type="button" className="auth-social-btn">
            <span className="auth-social-icon g">G</span> Sign Up With Google
          </button>
          <button type="button" className="auth-social-btn">
            <span className="auth-social-icon f">f</span> Sign Up With Facebook
          </button>
        </div>
        <div className="auth-sep">
          <span>OR</span>
        </div>
        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Username</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="johndoe"
            />
          </div>
          <div className="form-group">
            <label>Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="johndoe.banking@gmail.com"
            />
          </div>
          <div className="form-group auth-password-wrap">
            <label>Password</label>
            <div className="auth-password-input">
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="********"
              />
              <button
                type="button"
                className="auth-eye"
                onClick={() => setShowPassword(!showPassword)}
                aria-label="Toggle password"
              >
                {showPassword ? "🙈" : "👁"}
              </button>
            </div>
          </div>
          <label className="auth-checkbox auth-terms">
            <input
              type="checkbox"
              checked={agree}
              onChange={(e) => setAgree(e.target.checked)}
            />{" "}
            I have read and agree with terms & condition.
          </label>
          <button type="submit" className="btn-primary auth-submit">
            Create Account
          </button>
        </form>
        <p className="auth-switch">
          Already have an account?{" "}
          <button
            type="button"
            className="auth-link-btn"
            onClick={onNavigateSignIn}
          >
            Sign In
          </button>
        </p>
      </div>
      <AuthPanel />
    </section>
  );
}

function AuthOnlyLayout() {
  const [authPage, setAuthPage] = useState<"signin" | "signup">("signin");
  return (
    <div className="auth-fullpage">
      {authPage === "signin" ? (
        <SignInView onNavigateSignUp={() => setAuthPage("signup")} />
      ) : (
        <SignUpView onNavigateSignIn={() => setAuthPage("signin")} />
      )}
    </div>
  );
}

type PeriodFilter = "This Week" | "All Time";

function TransactionsView() {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [period, setPeriod] = useState<PeriodFilter>("This Week");
  const [periodOpen, setPeriodOpen] = useState(false);

  const filtered =
    period === "This Week"
      ? transactionsHistory.filter(
          (t) =>
            t.date.includes("February 18") || t.date.includes("February 19"),
        )
      : transactionsHistory;

  const toggle = (id: string) => {
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const toggleAll = () => {
    if (selected.size === filtered.length) setSelected(new Set());
    else setSelected(new Set(filtered.map((t) => t.id)));
  };

  return (
    <section className="transactions-section">
      <div className="card transactions-history-card">
        <div className="transactions-history-head">
          <div>
            <h3>Transactions History</h3>
            <p className="transactions-history-subtitle muted">
              Lorem ipsum dolor sit amet
            </p>
          </div>
          <div className="filter-dropdown-wrap">
            <button
              type="button"
              className="pill"
              onClick={() => setPeriodOpen(!periodOpen)}
            >
              {period} ▼
            </button>
            {periodOpen && (
              <div className="filter-dropdown">
                <button
                  type="button"
                  onClick={() => {
                    setPeriod("This Week");
                    setPeriodOpen(false);
                  }}
                >
                  This Week
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setPeriod("All Time");
                    setPeriodOpen(false);
                  }}
                >
                  All Time
                </button>
              </div>
            )}
          </div>
        </div>
        <div className="transactions-table-wrap">
          <table className="transactions-table">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    checked={
                      filtered.length > 0 && selected.size === filtered.length
                    }
                    onChange={toggleAll}
                    aria-label="Select all"
                  />
                </th>
                <th>Transaction ID</th>
                <th>Recipient</th>
                <th>Date</th>
                <th>Amount</th>
                <th>Card Name</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((t) => (
                <tr key={t.id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.has(t.id)}
                      onChange={() => toggle(t.id)}
                      aria-label={`Select ${t.name}`}
                    />
                  </td>
                  <td className="tx-id">{t.id}</td>
                  <td>
                    <div className="tx-recipient">
                      <img
                        src={`https://i.pravatar.cc/40?img=${t.img}`}
                        alt=""
                        className="tx-recipient-avatar"
                      />
                      <span>{t.name}</span>
                    </div>
                  </td>
                  <td className="muted">{t.date}</td>
                  <td className="tx-amount">
                    <span className="tx-amount-arrow">↑</span> {t.amount}
                  </td>
                  <td className="muted">{t.card}</td>
                  <td>
                    <span className={`status-badge status-${t.statusType}`}>
                      {t.status}
                    </span>
                  </td>
                  <td>
                    <span className="tx-dots">⋮</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

const PAGE_TITLE: Record<string, string> = {
  "Knowledge base": "FAQ",
  "404": "Error",
  "Protected Page": "Protected Password",
};

function App() {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState("Dashboard");
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const [invoicesExpanded, setInvoicesExpanded] = useState(false);
  const [utilitiesExpanded, setUtilitiesExpanded] = useState(false);
  const [authExpanded, setAuthExpanded] = useState(false);

  const isInvoicesActive =
    activeTab === "Invoice List" || activeTab === "Create Invoices";
  const invoicesExpandedShow = invoicesExpanded || isInvoicesActive;
  const utilitiesIds = [
    "Knowledge base",
    "404",
    "Protected Page",
    "Changelog",
    "License",
  ];
  const isUtilitiesActive = utilitiesIds.includes(activeTab);
  const utilitiesExpandedShow = utilitiesExpanded || isUtilitiesActive;
  const authIds = ["Sign In", "Sign Up"];
  const isAuthActive = authIds.includes(activeTab);
  const authExpandedShow = authExpanded || isAuthActive;

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (
        userMenuRef.current &&
        !userMenuRef.current.contains(e.target as Node)
      )
        setUserMenuOpen(false);
    };
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, []);

  if (!user) return <AuthOnlyLayout />;

  const expanded = (item: { id: string }) =>
    item.id === "Invoices"
      ? invoicesExpandedShow
      : item.id === "Utilities"
        ? utilitiesExpandedShow
        : item.id === "Authentication"
          ? authExpandedShow
          : false;
  const toggleExpanded = (item: { id: string }) => {
    if (item.id === "Invoices") setInvoicesExpanded(!invoicesExpandedShow);
    if (item.id === "Utilities") setUtilitiesExpanded(!utilitiesExpandedShow);
    if (item.id === "Authentication") setAuthExpanded(!authExpandedShow);
  };

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="logo">F MoneyFarm</div>
        <nav>
          {NAV_ITEMS.map((item) => {
            if (item.children) {
              const isExpanded = expanded(item);
              return (
                <div key={item.id} className="nav-group">
                  <div
                    className={`nav-item nav-item-parent ${activeTab === item.id ? "active" : ""} ${isExpanded ? "expanded" : ""}`}
                    onClick={() => toggleExpanded(item)}
                    onKeyDown={(e) => e.key === "Enter" && toggleExpanded(item)}
                    role="button"
                    tabIndex={0}
                  >
                    <span className="nav-dot" /> {item.label}
                    <span className="nav-chevron">
                      {isExpanded ? "▼" : "▶"}
                    </span>
                  </div>
                  {isExpanded &&
                    item.children.map((child) => (
                      <div
                        key={child.id}
                        className={`nav-item nav-item-child ${activeTab === child.id ? "active" : ""}`}
                        onClick={() => setActiveTab(child.id)}
                        onKeyDown={(e) =>
                          e.key === "Enter" && setActiveTab(child.id)
                        }
                        role="button"
                        tabIndex={0}
                      >
                        <span className="nav-dot" /> {child.label}
                      </div>
                    ))}
                </div>
              );
            }
            return (
              <div
                key={item.id}
                className={`nav-item ${activeTab === item.id ? "active" : ""}`}
                onClick={() => setActiveTab(item.id)}
                onKeyDown={(e) => e.key === "Enter" && setActiveTab(item.id)}
                role="button"
                tabIndex={0}
              >
                <span className="nav-dot" /> {item.label}
              </div>
            );
          })}
        </nav>
      </aside>

      <main className="content">
        <header className="topbar">
          <h1>{PAGE_TITLE[activeTab] ?? activeTab}</h1>
          <div className="top-actions">
            <input
              type="search"
              placeholder="Search here ..."
              aria-label="Search"
            />
            <span className="bell">
              🔔<span className="badge">3</span>
            </span>
            <div className="user-menu-wrap" ref={userMenuRef}>
              <button
                type="button"
                className="user-menu-trigger"
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                aria-expanded={userMenuOpen}
                aria-haspopup="true"
              >
                <img className="avatar" src={user.avatar} alt="" />
                <span className="avatar-chevron">▼</span>
              </button>
              {userMenuOpen && (
                <div className="user-menu-dropdown">
                  <span
                    className="muted"
                    style={{
                      padding: "8px 14px",
                      display: "block",
                      fontSize: 13,
                    }}
                  >
                    {user.email}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveTab("Setting");
                      setUserMenuOpen(false);
                    }}
                  >
                    Setting
                  </button>
                  <button
                    type="button"
                    className="danger"
                    onClick={() => {
                      logout();
                      setUserMenuOpen(false);
                    }}
                  >
                    Logout
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {activeTab === "Dashboard" && <DashboardView />}
        {activeTab === "My Wallet" && <MyWalletView />}
        {activeTab === "Transactions" && <TransactionsView />}
        {activeTab === "Invoice List" && <InvoiceListView />}
        {activeTab === "Create Invoices" && <CreateInvoicesView />}
        {activeTab === "Card Center" && <CardCenterView />}
        {activeTab === "Accounts" && <AccountsView />}
        {activeTab === "Setting" && <SettingView />}
        {activeTab === "Knowledge base" && <KnowledgeBaseView />}
        {activeTab === "404" && (
          <Error404View onGoHome={() => setActiveTab("Dashboard")} />
        )}
        {activeTab === "Protected Page" && <ProtectedPageView />}
        {activeTab === "Changelog" && <ChangelogView />}
        {activeTab === "License" && <LicenseView />}
        {activeTab === "Sign In" && (
          <SignInView
            onNavigateSignUp={() => setActiveTab("Sign Up")}
            onSignInSuccess={() => setActiveTab("Dashboard")}
          />
        )}
        {activeTab === "Sign Up" && (
          <SignUpView
            onNavigateSignIn={() => setActiveTab("Sign In")}
            onSignUpSuccess={() => setActiveTab("Dashboard")}
          />
        )}
        {![
          "Dashboard",
          "My Wallet",
          "Transactions",
          "Invoice List",
          "Create Invoices",
          "Card Center",
          "Accounts",
          "Setting",
          "Knowledge base",
          "404",
          "Protected Page",
          "Changelog",
          "License",
          "Sign In",
          "Sign Up",
        ].includes(activeTab) && (
          <section className="grid">
            <div className="card span-2">
              <h3>{activeTab}</h3>
              <p className="muted">Nội dung đang được xây dựng.</p>
            </div>
          </section>
        )}

        <footer className="foot">
          © MoneyFarm by Flowzai · License · Powered by Webflow
        </footer>
      </main>
    </div>
  );
}

export default App;
