import { useState } from "react";

const steps = ["Identity document", "Selfie check", "Review & submit"];

export default function KycView() {
  const [active, setActive] = useState(0);

  return (
    <section className="card kyc-card">
      <h3>KYC Verification</h3>
      <p className="muted">Verify your identity to unlock higher limits.</p>
      <div className="kyc-steps">
        {steps.map((step, index) => (
          <div
            key={step}
            className={`kyc-step ${index === active ? "active" : ""} ${index < active ? "done" : ""}`}
          >
            <span className="kyc-step-index">{index + 1}</span>
            <span>{step}</span>
          </div>
        ))}
      </div>
      {active === 0 && (
        <div className="kyc-upload">
          <label className="upload-drop">
            <span>Upload ID (front)</span>
            <input type="file" accept="image/*" />
          </label>
          <label className="upload-drop">
            <span>Upload ID (back)</span>
            <input type="file" accept="image/*" />
          </label>
        </div>
      )}
      {active === 1 && (
        <div className="kyc-upload">
          <label className="upload-drop">
            <span>Upload selfie</span>
            <input type="file" accept="image/*" />
          </label>
          <p className="muted small">
            Make sure your face is clear and well lit.
          </p>
        </div>
      )}
      {active === 2 && (
        <div className="kyc-review">
          <p>Review your documents and submit for verification.</p>
          <ul>
            <li>Valid government ID</li>
            <li>Clear selfie</li>
            <li>Matching name & birth date</li>
          </ul>
        </div>
      )}
      <div className="kyc-actions">
        <button
          type="button"
          className="pill"
          onClick={() => setActive((current) => Math.max(0, current - 1))}
          disabled={active === 0}
        >
          Back
        </button>
        <button
          type="button"
          className="btn-primary"
          onClick={() =>
            setActive((current) => Math.min(steps.length - 1, current + 1))
          }
        >
          {active === steps.length - 1 ? "Submit" : "Next"}
        </button>
      </div>
    </section>
  );
}
