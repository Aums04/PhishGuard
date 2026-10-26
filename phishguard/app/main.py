import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from urllib.parse import urlparse

from app.features import extract_features
from app.rules import evaluate as rule_evaluate
from app.model import predict as ml_predict, load_metrics
from app.storage import init_db, save_assessment, get_history
from app.report import build_report_pdf

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="wide")
init_db()


def combine_verdict(rule_result, ml_result):
    """Combine rule score and ML probability into one final verdict.
    Kept separate internally — this is just the display-level summary."""
    rule_pct = rule_result["score"] / 100
    ml_pct = ml_result["phishing_probability"]
    combined = 0.5 * rule_pct + 0.5 * ml_pct
    if combined >= 0.5:
        return "⚠️ Likely Phishing", combined
    elif combined >= 0.25:
        return "🟡 Suspicious — Review Further", combined
    else:
        return "✅ Likely Legitimate", combined


def page_assess():
    st.title("🛡️ PhishGuard — URL Security Assessment")
    st.caption(
        "Static analysis only — this tool does not visit or render the submitted URL. "
        "Results are decision support, not a guarantee."
    )

    url_input = st.text_input("Enter a URL to assess", placeholder="https://example.com/login")
    go_btn = st.button("Assess URL", type="primary")

    if go_btn and url_input.strip():
        features = extract_features(url_input)
        rule_result = rule_evaluate(features)
        ml_result = ml_predict(features)
        final_label, combined_score = combine_verdict(rule_result, ml_result)
        domain = features["hostname"] or urlparse(url_input).netloc

        assessment_id = save_assessment(domain, url_input, rule_result, ml_result, final_label)

        st.subheader("Overall Verdict")
        c1, c2, c3 = st.columns(3)
        c1.metric("Final Verdict", final_label)
        c2.metric("Rule Engine Score", f"{rule_result['score']}/100")
        c3.metric("ML Phishing Probability", f"{ml_result['phishing_probability']*100:.1f}%")

        st.divider()
        col_rules, col_ml = st.columns(2)

        with col_rules:
            st.subheader("📋 Rule-Based Findings")
            st.write(f"**Verdict:** {rule_result['verdict']} ({rule_result['score']}/100)")
            if rule_result["findings"]:
                for f in rule_result["findings"]:
                    sev_icon = {"low": "🟢", "medium": "🟡", "high": "🔴"}[f["severity"]]
                    st.markdown(f"{sev_icon} **{f['rule']}** — {f['evidence']}")
            else:
                st.success("No rule-based indicators triggered.")

        with col_ml:
            st.subheader("🤖 ML Model Assessment")
            st.write(f"**Predicted label:** {ml_result['label']}")
            st.write(f"**Phishing probability:** {ml_result['phishing_probability']*100:.1f}%")
            st.write("**Top contributing features (this URL):**")
            if ml_result["top_contributions"]:
                contrib_df = pd.DataFrame(ml_result["top_contributions"])
                st.dataframe(contrib_df, hide_index=True, use_container_width=True)
            else:
                st.info("No notable contributing features for this prediction.")

        st.divider()
        pdf_bytes = build_report_pdf(domain, rule_result, ml_result, final_label)
        st.download_button(
            "⬇️ Download PDF Report",
            data=pdf_bytes,
            file_name=f"phishguard_report_{assessment_id}.pdf",
            mime="application/pdf",
        )
    elif go_btn:
        st.warning("Please enter a URL first.")


def page_evaluation():
    st.title("📊 Model Evaluation")
    metrics = load_metrics()

    c1, c2, c3 = st.columns(3)
    c1.metric("Precision", f"{metrics['precision']*100:.1f}%")
    c2.metric("Recall", f"{metrics['recall']*100:.1f}%")
    c3.metric("F1 Score", f"{metrics['f1']*100:.1f}%")

    st.caption(
        f"Evaluated on a held-out test set of {metrics['test_size']} URLs "
        f"(trained on {metrics['train_size']}). "
        "⚠️ Dataset is a curated/synthetic academic sample with clearly separable "
        "classes by construction — these scores reflect that, not real-world "
        "generalization. See Limitations in the PRD."
    )

    st.subheader("Confusion Matrix")
    cm = metrics["confusion_matrix"]
    labels = metrics["confusion_matrix_labels"]
    fig = go.Figure(data=go.Heatmap(
        z=cm, x=[f"Predicted {l}" for l in labels], y=[f"Actual {l}" for l in labels],
        text=cm, texttemplate="%{text}", colorscale="Blues"
    ))
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Global Feature Importance")
    imp = metrics["feature_importances"]
    imp_df = pd.DataFrame(sorted(imp.items(), key=lambda x: x[1], reverse=True),
                           columns=["feature", "importance"])
    fig2 = px.bar(imp_df, x="importance", y="feature", orientation="h")
    fig2.update_layout(height=500, yaxis={"categoryorder": "total ascending"})
    st.plotly_chart(fig2, use_container_width=True)


def page_history():
    st.title("🕑 Assessment History")
    rows = get_history()
    if not rows:
        st.info("No assessments yet. Run one on the Assess URL page.")
        return
    df = pd.DataFrame(rows)
    verdict_filter = st.multiselect(
        "Filter by final verdict", options=sorted(df["final_verdict"].unique()),
        default=list(df["final_verdict"].unique())
    )
    filtered = df[df["final_verdict"].isin(verdict_filter)]
    st.dataframe(
        filtered[["id", "timestamp", "domain", "rule_score", "rule_verdict",
                  "ml_probability", "ml_label", "final_verdict"]],
        hide_index=True, use_container_width=True
    )
    st.caption("Note: only the domain and a hash are stored — full raw URLs are not persisted.")


PAGES = {
    "Assess URL": page_assess,
    "Model Evaluation": page_evaluation,
    "History": page_history,
}

st.sidebar.title("PhishGuard")
choice = st.sidebar.radio("Navigate", list(PAGES.keys()))
PAGES[choice]()
