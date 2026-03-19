import { useState } from "react";

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

export default function KnowledgeBaseView() {
  const [openGeneral, setOpenGeneral] = useState<number | null>(null);
  const [openOthers, setOpenOthers] = useState<number | null>(null);

  return (
    <section className="utility-faq-section">
      <div className="card faq-card">
        <h3>General Inquires</h3>
        <ul className="faq-list">
          {faqGeneral.map((item, index) => (
            <li key={index} className="faq-item">
              <div
                className="faq-item-inner"
                onClick={() =>
                  setOpenGeneral(openGeneral === index ? null : index)
                }
                role="button"
                tabIndex={0}
                onKeyDown={(event) =>
                  event.key === "Enter" &&
                  setOpenGeneral(openGeneral === index ? null : index)
                }
              >
                <span className="faq-q">{item.q}</span>
                <span className="faq-info-icon">
                  {openGeneral === index ? "-" : "i"}
                </span>
              </div>
              {(item.detail || openGeneral === index) && (
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
          {faqOthers.map((item, index) => (
            <li key={index} className="faq-item">
              <div
                className="faq-item-inner"
                onClick={() =>
                  setOpenOthers(openOthers === index ? null : index)
                }
                role="button"
                tabIndex={0}
                onKeyDown={(event) =>
                  event.key === "Enter" &&
                  setOpenOthers(openOthers === index ? null : index)
                }
              >
                <span className="faq-q">{item.q}</span>
                <span className="faq-info-icon">
                  {openOthers === index ? "-" : "i"}
                </span>
              </div>
              {openOthers === index && (
                <p className="muted faq-detail">No additional details.</p>
              )}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
