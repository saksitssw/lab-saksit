#!/usr/bin/env python3
"""
Auto-grader สำหรับ Network Security Lab
รันโดย GitHub Actions ทุกครั้งที่นักศึกษา push
"""
import yaml, sys, os, json
from pathlib import Path

# ========== เฉลยทั้งหมด ==========
ANSWER_KEYS = {
    "lab01": {
        "total": 20,
        "questions": {
            "q1_scanner_ip":      {"answers": ["10.10.60.50"], "score": 1.5},
            "q1_target_ip":       {"answers": ["10.10.60.100"], "score": 1.5},
            "q2_port_22":         {"answers": ["open"], "score": 0.75},
            "q2_port_80":         {"answers": ["open"], "score": 0.75},
            "q2_port_443":        {"answers": ["closed"], "score": 0.75},
            "q2_port_139":        {"answers": ["open"], "score": 0.75},
            "q2_port_445":        {"answers": ["open"], "score": 0.75},
            "q2_port_3389":       {"answers": ["closed"], "score": 0.75},
            "q2_port_8080":       {"answers": ["filtered"], "score": 0.75},
            "q2_port_21":         {"answers": ["filtered"], "score": 0.75},
            "q4_filter_scanner":  {"answers": ["ip.src == 10.10.60.50","ip.src==10.10.60.50"], "score": 2},
            "q4_filter_open":     {"answers": ["tcp.flags == 0x012","tcp.flags==0x012","tcp.flags == 0x12","tcp.flags==0x12"], "score": 2},
        }
    },
    "lab02": {
        "total": 20,
        "questions": {
            "q1_client_ip":  {"answers": ["10.10.70.30"], "score": 1},
            "q1_server_ip":  {"answers": ["10.10.70.10"], "score": 1},
            "q3_username":   {"answers": ["student01"], "score": 2},
            "q3_password":   {"answers": ["summer2026!", "Summer2026!"], "score": 2},
            "q4_code_331":   {"answers": ["password required","331 password required"], "score": 2},
            "q4_code_230":   {"answers": ["login successful","230 login successful","230 ok"], "score": 2},
        }
    },
    "lab03": {
        "total": 20,
        "questions": {
            "q1_victim_ip":           {"answers": ["10.10.80.20"], "score": 1},
            "q1_victim_mac":          {"answers": ["aa:aa:aa:aa:aa:20"], "score": 0.5},
            "q1_gateway_ip":          {"answers": ["10.10.80.1"], "score": 1},
            "q1_gateway_mac":         {"answers": ["aa:aa:aa:aa:aa:01"], "score": 0.5},
            "q1_attacker_ip":         {"answers": ["10.10.80.66"], "score": 1},
            "q1_attacker_mac":        {"answers": ["de:ad:be:ef:00:66"], "score": 0.5},
            "q2_arp_request_count":   {"answers": ["1"], "score": 1},
            "q2_arp_reply_count":     {"answers": ["10"], "score": 1},
            "q2_attack_start_packet": {"answers": ["3"], "score": 2},
            "q3_packet2_mac":         {"answers": ["aa:aa:aa:aa:aa:01"], "score": 1.5},
            "q3_packet3_mac":         {"answers": ["de:ad:be:ef:00:66"], "score": 1.5},
        }
    },
    "lab04": {
        "total": 20,
        "questions": {
            "q1_infected_ip":    {"answers": ["10.10.90.15"], "score": 1},
            "q1_dns_server":     {"answers": ["10.10.90.1"], "score": 1},
            "q2_query1":         {"answers": ["on2hkzdfnz2f64tfmnxxezdtl5rgc5ddnayq.exfil.test"], "score": 1.5},
            "q2_query2":         {"answers": ["m5zgczdfonptembsgzpxgzlnmvzxizlsge.exfil.test"], "score": 1.5},
            "q2_query3":         {"answers": ["mzuw4ylml5rwq5lonnpwk33g.exfil.test"], "score": 1},
            "q4_decoded_text":   {"answers": ["student_records_batch1"], "score": 5},
            "q5_wireshark_filter": {"answers": [
                'dns.qry.name matches "[a-z2-7]{30,}"',
                "dns.qry.name contains exfil",
                "dns"
            ], "score": 3},
        }
    },
    "lab05": {
        "total": 20,
        "questions": {
            "q1_attacker_ip":    {"answers": ["10.10.100.77"], "score": 1},
            "q1_server_ip":      {"answers": ["10.10.100.10"], "score": 1},
            "q2_req1_method":    {"answers": ["get","GET"], "score": 1},
            "q2_req1_response":  {"answers": ["200","200 ok"], "score": 1},
            "q2_req2_method":    {"answers": ["get","GET"], "score": 1},
            "q2_req2_response":  {"answers": ["200","200 ok"], "score": 1},
            "q2_req3_method":    {"answers": ["get","GET"], "score": 1},
            "q2_req3_response":  {"answers": ["500","500 internal server error"], "score": 1},
            "q3_sqli_payload":   {"answers": ["' or '1'='1","or 1=1","' OR '1'='1"], "score": 4},
            "q4_stolen_data":    {"answers": ["admin:5f4dcc3b5aa765d61d8327deb882cf99","username password hash"], "score": 4},
        }
    },
    "lab06": {
        "total": 20,
        "questions": {
            "q1_attacker_ip":      {"answers": ["10.10.110.88"], "score": 1},
            "q1_server_ip":        {"answers": ["10.10.110.10"], "score": 1},
            "q2_total_attempts":   {"answers": ["5"], "score": 2},
            "q2_interval_seconds": {"answers": ["1.35","1.35 seconds","1.35 วินาที"], "score": 2},
            "q3_pass1":            {"answers": ["123456"], "score": 1},
            "q3_pass2":            {"answers": ["password"], "score": 1},
            "q3_pass3":            {"answers": ["admin123"], "score": 1},
            "q3_pass4":            {"answers": ["letmein"], "score": 1},
            "q3_pass5":            {"answers": ["winter2026!","Winter2026!"], "score": 1},
            "q4_correct_password": {"answers": ["winter2026!","Winter2026!"], "score": 4},
        }
    },
    "lab07": {
        "total": 20,
        "questions": {
            "q1_infected_ip":     {"answers": ["10.10.120.44"], "score": 1},
            "q1_c2_ip":           {"answers": ["203.0.113.99"], "score": 1},
            "q1_c2_domain":       {"answers": ["update-service.test"], "score": 1},
            "q2_beacon_count":    {"answers": ["5"], "score": 2},
            "q2_beacon_interval": {"answers": ["60","60 seconds","60 วินาที"], "score": 2},
            "q4_command":         {"answers": ["encrypt_files","cmd=encrypt_files","ENCRYPT_FILES"], "score": 4},
        }
    },
    "lab08": {
        "total": 20,
        "questions": {
            "q1_victim_ip":      {"answers": ["10.10.130.55"], "score": 1},
            "q1_victim_port":    {"answers": ["49800"], "score": 0.5},
            "q1_attacker_ip":    {"answers": ["203.0.113.77"], "score": 1},
            "q1_attacker_port":  {"answers": ["4444"], "score": 0.5},
            "q1_who_initiated":  {"answers": ["victim","10.10.130.55","เครื่อง victim"], "score": 1},
            "q3_cmd1":           {"answers": ["whoami"], "score": 1},
            "q3_out1":           {"answers": ["nt authority\\system","nt authority/system"], "score": 1},
            "q3_cmd2":           {"answers": ["hostname"], "score": 1},
            "q3_out2":           {"answers": ["desktop-school01","DESKTOP-SCHOOL01"], "score": 1},
            "q4_privilege":      {"answers": ["nt authority\\system","system","administrator"], "score": 2},
        }
    },
    "lab09": {
        "total": 20,
        "questions": {
            "q1_mail_from":      {"answers": ["it-support@sch00l.test"], "score": 1},
            "q1_rcpt_to":        {"answers": ["student01@school.test"], "score": 1},
            "q1_from_header":    {"answers": ["it-support@sch00l.test","IT Support <it-support@sch00l.test>"], "score": 1},
            "q3_phishing_url":   {"answers": ["http://school-verify.test/login","school-verify.test"], "score": 3},
            "q3_is_real":        {"answers": ["no","ไม่ใช่","ไม่","false"], "score": 2},
            "q4_username":       {"answers": ["student01"], "score": 2},
            "q4_password":       {"answers": ["school@2026","School@2026"], "score": 2},
            "q4_response_code":  {"answers": ["302","302 found"], "score": 2},
        }
    },
    "lab10": {
        "total": 20,
        "questions": {
            "q1_ap_mac":         {"answers": ["aa:bb:cc:dd:ee:01"], "score": 1},
            "q1_client_mac":     {"answers": ["11:22:33:44:55:66"], "score": 1},
            "q1_attacker_mac":   {"answers": ["de:ad:be:ef:ca:fe"], "score": 1},
            "q1_ssid":           {"answers": ["schoolwifi","SchoolWiFi"], "score": 1},
            "q2_deauth_count":   {"answers": ["10"], "score": 2},
            "q3_spoofed_mac":    {"answers": ["aa:bb:cc:dd:ee:01","ap mac","mac ของ ap"], "score": 4},
        }
    },
}

def normalize(text):
    """ทำให้คำตอบเป็นรูปแบบมาตรฐานก่อนเปรียบเทียบ"""
    if text is None:
        return ""
    return str(text).strip().lower().replace("  ", " ")

def grade_lab(lab_id, student_file):
    if lab_id not in ANSWER_KEYS:
        return None, f"ไม่พบเฉลยสำหรับ {lab_id}"

    try:
        with open(student_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        return None, f"อ่านไฟล์ไม่ได้: {e}"

    if not data or "answers" not in data:
        return None, "ไม่พบ key 'answers' ในไฟล์"

    key = ANSWER_KEYS[lab_id]
    student_answers = data.get("answers", {})
    student_id = data.get("student_id", "unknown")
    student_name = data.get("student_name", "unknown")

    results = []
    total_earned = 0
    auto_gradable_total = 0

    for q_key, q_data in key["questions"].items():
        correct_answers = [normalize(a) for a in q_data["answers"]]
        student_ans = normalize(student_answers.get(q_key, ""))
        q_score = q_data["score"]
        auto_gradable_total += q_score

        is_correct = student_ans in correct_answers
        # ตรวจแบบ partial match สำหรับคำตอบที่เป็น substring
        if not is_correct and student_ans:
            is_correct = any(ca in student_ans or student_ans in ca
                           for ca in correct_answers if len(ca) > 3)

        earned = q_score if is_correct else 0
        total_earned += earned
        results.append({
            "question": q_key,
            "student_answer": str(student_answers.get(q_key, "")),
            "correct": is_correct,
            "earned": earned,
            "max": q_score
        })

    return {
        "student_id": student_id,
        "student_name": student_name,
        "lab": lab_id,
        "score": round(total_earned, 2),
        "auto_gradable_max": round(auto_gradable_total, 2),
        "lab_total": key["total"],
        "results": results
    }, None


def main():
    answers_dir = Path("answers")
    all_results = []
    total_score = 0
    total_max = 0

    print("=" * 60)
    print("📊 ผลการตรวจ Network Security Lab")
    print("=" * 60)

    # ตรวจทุก lab ที่มีไฟล์
    for lab_num in range(1, 11):
        lab_id = f"lab{lab_num:02d}"
        lab_file = answers_dir / f"{lab_id}.yml"

        if not lab_file.exists():
            continue

        result, error = grade_lab(lab_id, lab_file)
        if error:
            print(f"\n❌ {lab_id}: {error}")
            continue

        all_results.append(result)
        total_score += result["score"]
        total_max += result["auto_gradable_max"]

        # แสดงผลแต่ละ lab
        pct = (result["score"] / result["auto_gradable_max"] * 100) if result["auto_gradable_max"] > 0 else 0
        emoji = "✅" if pct >= 70 else "⚠️" if pct >= 50 else "❌"
        print(f"\n{emoji} {lab_id.upper()} — {result['student_name']} ({result['student_id']})")
        print(f"   คะแนน: {result['score']}/{result['auto_gradable_max']} ({pct:.1f}%)")
        print(f"   รายละเอียด:")
        for r in result["results"]:
            mark = "✓" if r["correct"] else "✗"
            print(f"     [{mark}] {r['question']}: {r['student_answer'][:50]} (+{r['earned']}/{r['max']})")

    # สรุปรวม
    print("\n" + "=" * 60)
    print(f"📈 สรุปรวมทั้งหมด: {round(total_score, 2)}/{round(total_max, 2)} คะแนน")
    print("=" * 60)

    # บันทึก JSON result
    with open("grade_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "total_score": round(total_score, 2),
            "total_max": round(total_max, 2),
            "labs": all_results
        }, f, ensure_ascii=False, indent=2)

    print("\n💾 บันทึกผลไว้ที่ grade_results.json")

    # exit code 0 เสมอ (ไม่ fail workflow แม้คะแนนต่ำ)
    sys.exit(0)

if __name__ == "__main__":
    main()
