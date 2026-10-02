import os
import json

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise ValueError("OPENAI_API_KEY was not found in your .env file.")

client = OpenAI(api_key=api_key)


def analyze_with_ai(alert):
    """
    Takes a security alert as a Python dictionary
    and returns a structured AI security analysis.
    """

    alert_text = json.dumps(alert, indent=2)

    prompt = f"""
You are assisting a cybersecurity analyst.

Analyze the security alert below using only the evidence provided.

SECURITY ALERT:
{alert_text}

Severity means investigation priority based on the observed behavior,
not certainty that a compromise succeeded.

Use this rubric:
- Low: Little evidence of suspicious behavior; routine activity is plausible.
- Medium: Suspicious activity warrants investigation, but indicators are limited.
- High: A strongly suspicious combination of indicators warrants urgent investigation,
  even if successful compromise is not confirmed.
- Critical: Evidence supports an ongoing incident with severe impact requiring
  immediate attention. Do not infer severe impact from missing information.

Explain uncertainty separately. Do not treat missing proof of successful
compromise as sufficient reason by itself to lower investigation priority.

Requirements:
- Do not assume information that is not present.
- Identify suspicious behavior supported by the evidence.
- Map relevant behavior to MITRE ATT&CK where appropriate.
- Recommend investigation steps only.
- Do not take or recommend automatic remediation actions.
- A human analyst will make the final decision.
"""

    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt,

        text={
            "format": {
                "type": "json_schema",
                "name": "security_analysis",
                "strict": True,

                "schema": {
                    "type": "object",

                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": [
                                "Low",
                                "Medium",
                                "High",
                                "Critical"
                            ]
                        },

                        "confidence": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 100
                        },

                        "mitre_techniques": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },

                        "evidence": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },

                        "explanation": {
                            "type": "string"
                        },

                        "recommended_steps": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    },

                    "required": [
                        "severity",
                        "confidence",
                        "mitre_techniques",
                        "evidence",
                        "explanation",
                        "recommended_steps"
                    ],

                    "additionalProperties": False
                }
            }
        }
    )

    analysis = json.loads(response.output_text)

    return analysis