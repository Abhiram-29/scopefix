# ScopeFix: Autonomous Open-Source Vulnerability Remediation
### Detect. Strategize. Surgically Repair

ScopeFix is an open-source framework designed to resolve security vulnerabilities in software codebases. By utilizing a novel Strategist-First Architecture powered exclusively by open-weights Large Language Models (LLMs), it unburdens human developers from the overwhelming volume of routine security patches.

In the modern DevSecOps landscape, thousands of vulnerabilities are detected daily. Human developers simply cannot keep up, leading to a massive backlog of "Low" and "Medium" complexity issues that remain unpatched for months. ScopeFix aims to clear this "Security Debt" by autonomously resolving these vulnerabilities, allowing human engineers to focus on high-severity, architectural security challenges.

## The Problem
Automated vulnerability scanning tools like Bandit, Semgrep are able to pinpont thousands of security issues in a jiffy. It takes a lot of human effort to analyze and fix these vulnerabilities leading to Security Debt. Most projects don't have enough resources to fix every detected vulnerability. Studies show that even after 6 months only 56% of detected vulnerabilities are fixed.

## Solution: The Strategy first architecture

Scopefix introduces a strategist agent to the repair loop. Instead of blindly asking an LLM to "fix this code," our pipeline mimics a human engineering workflow: Plan first, then Code. 

#### The Strategist (Qwen3-32b)

Before any code is written, the strategist analyzes vulnerability report, source code and common methods to fix the vulnerability (obtained to web scraping) to generate a repair plan. 
It defines the root cause of the vulnerability and provides guidance to the fixer. <br>
<b>Impact:</b> This guidance allows the smaller Level 1 model to achieve significantly higher fix rates than if it were working alone.

#### Level 1 Fixer (Qwen3-32B)

Qwen3-32B is used as it is capable despite being a lightweight model and high availability of inference providers for it.
<b>Function</b>: It takes the Strategist's plan and executes a surgical patch.
<b>Efficiency</b>: Because it follows a strict plan, it effectively resolves the majority of routine vulnerabilities (e.g., input validation, secure defaults) with minimal compute overhead.

#### Level 2 Fixer (DeepSeek-R1)

DeepSeek-R1 was choosen for high availability of inference providers and relatively larger context window and coding capabilities. Other opensource models like glm-4.7, qwen3-max and kimi-k2-thinking are better suited but were not chosen due to lack of serverless inference providers.

<b>Function<b>: Leverages a massive context window and advanced reasoning capabilities to handle complex, logic-heavy vulnerabilities.





# Local Setup & Usage Instructions

## 1. Clone the Repository

Open your terminal and clone the repository to your local machine:

```bash
git clone [https://github.com/abhiram-29/scopefix.git](https://github.com/abhiram-29/scopefix.git)
cd scopefix
 ```

## 2. Setup Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

refer to the <b>.env.example<b> file to configure your environment variables

### 5. Run the remediation loop
To fix a vulnerability in a specific file, you need to pass the file path to the fix_vuln function inside fix_loop.py

```bash
python fix_loop.py
```