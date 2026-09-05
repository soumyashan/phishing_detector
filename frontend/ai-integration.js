// ============================================================
// AegisMail AI/ML Integration
// Connects the existing frontend to the FastAPI phishing detector
// ============================================================

(function () {
  "use strict";

  const API_ENDPOINT = "/predict";

  /**
   * Convert backend risk level to the frontend's existing
   * risk-level vocabulary.
   */
  function mapRiskLevel(score) {
    const risk = Number(score) || 0;

    if (risk >= 80) return "critical";
    if (risk >= 60) return "high";
    if (risk >= 30) return "medium";

    return "clean";
  }

  /**
   * Call the real Python AI/ML backend.
   */
  async function runAIAnalysis(emailText) {
    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email_text: emailText
      })
    });

    if (!response.ok) {
      let message = `AI server returned HTTP ${response.status}`;

      try {
        const errorData = await response.json();

        if (errorData.detail) {
          message = errorData.detail;
        }
      } catch (_) {
        // Keep the default HTTP error message.
      }

      throw new Error(message);
    }

    return await response.json();
  }

  /**
   * Merge the real backend AI result into the existing
   * AegisMail caseData object.
   */
  function mergeAIResult(caseData, aiResult) {
    const riskScore = Number(aiResult.risk_score) || 0;

    caseData.aiAnalysis = {
      prediction: aiResult.prediction || "UNKNOWN",
      riskScore: riskScore,
      phishingProbability: Number(aiResult.phishing_probability) || 0,
      aiRiskScore: Number(aiResult.ai_risk_score) || 0,
      securityRiskScore: Number(aiResult.security_risk_score) || 0,
      reasons: Array.isArray(aiResult.reasons)
        ? aiResult.reasons
        : []
    };

    // The REAL backend result becomes the authoritative
    // classification shown by the dashboard.
    caseData.classification = aiResult.prediction || "UNKNOWN";
    caseData.riskScore = Number(riskScore.toFixed(2));
    caseData.riskLevel = mapRiskLevel(riskScore);

    // This is now a real analysis, not one of the frontend demos.
    caseData.isDemo = false;

    return caseData;
  }

  /**
   * Replace the existing frontend analysis function.
   *
   * Original flow:
   *   parser -> local heuristic -> scan
   *
   * New flow:
   *   parser -> FastAPI -> calibrated SVM + security engine -> scan
   */
  window.analyzeEmailContent = async function (content, fileName) {
    const result = parseEmailContent(content, fileName);

    if (result.error) {
      showUploadError(result.message);
      return;
    }

    // Tell the user that the actual Python AI engine is running.
    showToast("Running AI/ML phishing analysis...", "info");

    try {
      const aiResult = await runAIAnalysis(content);

      mergeAIResult(result, aiResult);

      console.log("=== AegisMail AI/ML Analysis ===");
      console.log("Prediction:", aiResult.prediction);
      console.log("Final Risk:", aiResult.risk_score);
      console.log("Phishing Probability:", aiResult.phishing_probability);
      console.log("AI/SVM Risk:", aiResult.ai_risk_score);
      console.log("Security Risk:", aiResult.security_risk_score);
      console.log("Reasons:", aiResult.reasons);

      // Continue through the EXISTING AegisMail scan animation
      // and investigation dashboard.
      triggerScan(result);

    } catch (error) {
      console.error("AI/ML analysis failed:", error);

      showUploadError(
        "AI analysis failed. Make sure the FastAPI server is running and try again."
      );

      showToast(
        "AI analysis service unavailable",
        "error"
      );
    }
  };

  /**
   * Expose the functions for debugging if needed.
   */
  window.AegisMailAI = {
    runAIAnalysis,
    mergeAIResult,
    mapRiskLevel
  };

  console.log("AegisMail AI/ML integration loaded.");
})();