# 🛡️ CyberGuard PTaaS - Penetration Test as a Service

<div align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=600&size=28&pause=1000&color=00D9FF&center=true&vCenter=true&width=800&lines=Automated+Penetration+Testing;AI-Powered+Vulnerability+Assessment;Web+%26+Network+Security+Scanner;Enterprise-Grade+Security+Platform" alt="Typing SVG" />
</div>

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=120&section=header&text=&fontSize=0&animation=twinkling"/>

## 🎯 Project Summary

**CyberGuard PTaaS** is a comprehensive Penetration Testing as a Service platform designed to assess both Web and Network targets. It operates through a fully automated, multi-phase testing pipeline integrated with advanced AI models for intelligent analysis and reporting.

---

## 🧪 Testing Lifecycle

CyberGuard operates in **5 key phases**:

### 1️⃣ Information Gathering
* Network discovery, port scanning
* Web reconnaissance & DNS analysis

### 2️⃣ Vulnerability Assessment
* Automated vulnerability scanning (CVE-based)
* Static and dynamic analysis

### 3️⃣ AI Analysis via **DeepSeek AI**
* 📊 Generates a **Risk Score**
* 🔍 Predicts **Expected Vulnerabilities** based on the collected data

### 4️⃣ Exploitation
* CVE-based exploitation
* Validating expected vulnerabilities
* Eliminating false positives with real PoC

### 5️⃣ Gemini AI Report Generation
* Comprehensive security assessment report via API
* Professional documentation with actionable recommendations

---

## 🤖 AI Integration

* **DeepSeek AI** → Risk scoring and vulnerability prediction
* **Gemini AI** → Generates a detailed **Security Assessment Report** via API

📁 All results are stored in a structured MongoDB document format per phase, pre-processed and filtered before report generation.

---

## ⚙️ Architecture Overview

```mermaid
graph TB
    A[Target System] --> B[Information Gathering]
    B --> C[Vulnerability Assessment]
    C --> D[DeepSeek AI Analysis]
    D --> E[Exploitation Engine]
    E --> F[Database Storage]
    F --> G[Report Generator]
    G --> H[Gemini AI API]
    H --> I[Final Security Report]
    
    style D fill:#ff6b6b
    style H fill:#4ecdc4
    style I fill:#45b7d1
```

---

🔗 [GitHub - mohammad-almohtaseb/cyber_guard](https://github.com/mohammad-almohtaseb/cyber_guard)

---

## 👥 Team & Contact

<div align="center">
  
[![Mohammad Al-mohtaseb](https://img.shields.io/badge/-Mohammad%20Al--mohtaseb-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/mohammad-al-mohtaseb-226134315)
[![Omar Amarah](https://img.shields.io/badge/-Omar%20Amarah-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/omar-amarah-594499302/)
[![Email](https://img.shields.io/badge/-Contact%20Us-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:mohammad.almohtaseb11@gmail.com)
[![GitHub](https://img.shields.io/badge/-Follow%20Updates-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/mohammad-almohtaseb)
  
</div>

---

<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=120&section=footer&text=&fontSize=0&animation=twinkling"/>
  
  ### 🛡️ "Security is not a product, but a process. CyberGuard makes that process intelligent."
  
  
  **⭐ Created by [Mohammad Al-mohtaseb](mailto:mohammad.almohtaseb11@gmail.com) and [Omar Amarah](mailto:omaramara@gmail.com) 🛡️**
</div>
