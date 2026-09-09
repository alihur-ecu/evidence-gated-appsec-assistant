from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def finding_detail():
    finding = {
        "finding_id": "F-0001",
        "finding_type": "Potential SQL Injection",
        "source_file": "vulnerable_sqli.php",
        "parameter": "id",
        "cwe": "CWE-89",
        "reason": (
            "The LLM identified a potential SQL injection vulnerability "
            "in the id parameter based on the supplied source-code context."
        ),
        "llm_status": "PROPOSED",
        "verification_status": "PENDING",
        "risk": "HIGH",
        "human_decision": None,
    }

    return render_template("finding_detail.html", finding=finding)


if __name__ == "__main__":
    app.run(debug=True)