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
    statusType: "completed",
    status: "Paid",
    img: 3,
  },
  {
    id: "#VM056DL5",
    name: "Amazon",
    date: "7 February, 2021",
    amount: "$95",
    statusType: "canceled",
    status: "Overdue",
    img: 6,
  },
];

export default function InvoiceListView() {
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
              {invoiceListData.map((invoice) => (
                <tr key={invoice.id + invoice.date}>
                  <td className="tx-id">{invoice.id}</td>
                  <td>
                    <div className="tx-recipient">
                      <img
                        src={`https://i.pravatar.cc/40?img=${invoice.img}`}
                        alt=""
                        className="tx-recipient-avatar"
                      />
                      <span>{invoice.name}</span>
                    </div>
                  </td>
                  <td className="muted">{invoice.date}</td>
                  <td className="tx-amount">{invoice.amount}</td>
                  <td>
                    <span
                      className={`status-badge status-${invoice.statusType}`}
                    >
                      {invoice.status}
                    </span>
                  </td>
                  <td>
                    <span className="tx-dots">...</span>
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
