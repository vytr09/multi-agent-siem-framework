#!/usr/bin/env python3
"""
Script để trích xuất các lệnh tấn công từ real_attackgen_results.json
"""

import json
import csv
from typing import List, Dict
from pathlib import Path


def load_attack_data(file_path: str) -> Dict:
    """Load dữ liệu từ file JSON"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_commands(data: Dict) -> List[Dict]:
    """Trích xuất các command từ dữ liệu"""
    commands = []
    
    attack_commands = data.get('execution_result', {}).get('attack_commands', [])
    
    for cmd in attack_commands:
        command_info = {
            'command_id': cmd.get('command_id'),
            'ttp_id': cmd.get('ttp_id'),
            'mitre_attack_id': cmd.get('mitre_attack_id'),
            'technique_name': cmd.get('technique_name'),
            'tactic': cmd.get('tactic'),
            'platform': cmd.get('platform'),
            'name': cmd.get('name'),
            'command': cmd.get('command'),
            'explanation': cmd.get('explanation'),
            'indicators': ', '.join(cmd.get('indicators', [])),
            'prerequisites': ', '.join(cmd.get('prerequisites', [])),
            'cleanup': cmd.get('cleanup'),
            'threat_actor': cmd.get('metadata', {}).get('threat_actor', ''),
            'campaign': cmd.get('metadata', {}).get('campaign', ''),
            'confidence_score': cmd.get('confidence_score')
        }
        commands.append(command_info)
    
    return commands


def save_to_csv(commands: List[Dict], output_file: str):
    """Lưu commands vào file CSV"""
    if not commands:
        print("Không có dữ liệu để lưu!")
        return
    
    fieldnames = commands[0].keys()
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(commands)
    
    print(f"✓ Đã lưu {len(commands)} commands vào {output_file}")


def save_to_json(commands: List[Dict], output_file: str):
    """Lưu commands vào file JSON"""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(commands, f, indent=2, ensure_ascii=False)
    
    print(f"✓ Đã lưu {len(commands)} commands vào {output_file}")


def generate_test_scripts(commands: List[Dict], output_dir: str):
    """Tạo các script test cho từng platform"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Nhóm commands theo platform
    windows_commands = [c for c in commands if c['platform'] == 'windows']
    linux_commands = [c for c in commands if c['platform'] == 'linux']
    
    # Tạo Windows batch script
    if windows_commands:
        windows_script = Path(output_dir) / "test_windows_attacks.bat"
        with open(windows_script, 'w', encoding='utf-8') as f:
            f.write("@echo off\n")
            f.write("REM Windows Attack Commands Test Script\n")
            f.write("REM WARNING: Run in isolated test environment only!\n\n")
            
            for i, cmd in enumerate(windows_commands, 1):
                f.write(f"REM ========== Test {i}: {cmd['name']} ==========\n")
                f.write(f"REM TTP: {cmd['mitre_attack_id']} - {cmd['technique_name']}\n")
                f.write(f"REM Tactic: {cmd['tactic']}\n")
                f.write(f"echo Executing: {cmd['name']}\n")
                f.write(f"{cmd['command']}\n")
                f.write(f"echo Cleanup: {cmd['cleanup']}\n")
                f.write(f"REM {cmd['cleanup']}\n")
                f.write("echo.\n\n")
        
        print(f"✓ Đã tạo Windows test script: {windows_script}")
    
    # Tạo Linux bash script
    if linux_commands:
        linux_script = Path(output_dir) / "test_linux_attacks.sh"
        with open(linux_script, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\n")
            f.write("# Linux Attack Commands Test Script\n")
            f.write("# WARNING: Run in isolated test environment only!\n\n")
            
            for i, cmd in enumerate(linux_commands, 1):
                f.write(f"# ========== Test {i}: {cmd['name']} ==========\n")
                f.write(f"# TTP: {cmd['mitre_attack_id']} - {cmd['technique_name']}\n")
                f.write(f"# Tactic: {cmd['tactic']}\n")
                f.write(f"echo \"Executing: {cmd['name']}\"\n")
                f.write(f"{cmd['command']}\n")
                f.write(f"echo \"Cleanup: {cmd['cleanup']}\"\n")
                f.write(f"# {cmd['cleanup']}\n")
                f.write("echo\n\n")
        
        # Make script executable
        linux_script.chmod(0o755)
        print(f"✓ Đã tạo Linux test script: {linux_script}")


def print_summary(commands: List[Dict]):
    """In tóm tắt về các commands"""
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    total = len(commands)
    print(f"Tổng số commands: {total}")
    
    # Thống kê theo platform
    platforms = {}
    for cmd in commands:
        platform = cmd['platform']
        platforms[platform] = platforms.get(platform, 0) + 1
    
    print("\nTheo Platform:")
    for platform, count in platforms.items():
        print(f"  - {platform}: {count} commands")
    
    # Thống kê theo tactic
    tactics = {}
    for cmd in commands:
        tactic = cmd['tactic']
        tactics[tactic] = tactics.get(tactic, 0) + 1
    
    print("\nTheo Tactic:")
    for tactic, count in sorted(tactics.items()):
        print(f"  - {tactic}: {count} commands")
    
    # Thống kê theo MITRE technique
    techniques = {}
    for cmd in commands:
        tech = f"{cmd['mitre_attack_id']} - {cmd['technique_name']}"
        techniques[tech] = techniques.get(tech, 0) + 1
    
    print("\nTheo MITRE Technique:")
    for tech, count in sorted(techniques.items()):
        print(f"  - {tech}: {count} commands")


def main():
    # Đường dẫn file input (relative to script location)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent  # tests/siem -> tests -> project_root
    input_file = project_root / "data" / "attackgen" / "real_attackgen_results.json"
    
    # Kiểm tra file tồn tại
    if not input_file.exists():
        print(f"❌ Không tìm thấy file: {input_file}")
        print(f"   Script đang chạy từ: {script_dir}")
        print(f"   Project root: {project_root}")
        return
    
    # Load dữ liệu
    print(f"Đang đọc dữ liệu từ {input_file}...")
    data = load_attack_data(str(input_file))
    
    # Trích xuất commands
    print("Đang trích xuất commands...")
    commands = extract_commands(data)
    
    # In summary
    print_summary(commands)
    
    # Tạo output directory (trong tests/siem/)
    output_dir = script_dir / "extracted_commands"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Lưu vào các format khác nhau
    print(f"\nĐang lưu dữ liệu vào thư mục {output_dir}/...")
    save_to_csv(commands, str(output_dir / "attack_commands.csv"))
    save_to_json(commands, str(output_dir / "attack_commands.json"))
    
    # Tạo test scripts
    print("\nĐang tạo test scripts...")
    generate_test_scripts(commands, str(output_dir / "test_scripts"))
    
    print("\n" + "="*60)
    print("HOÀN THÀNH!")
    print("="*60)
    print(f"\nCác file đã được tạo trong thư mục '{output_dir.relative_to(script_dir)}':")
    print("  - attack_commands.csv: Danh sách commands dạng CSV")
    print("  - attack_commands.json: Danh sách commands dạng JSON")
    print("  - test_scripts/test_windows_attacks.bat: Script test cho Windows")
    print("  - test_scripts/test_linux_attacks.sh: Script test cho Linux")
    print("\n⚠️  CẢNH BÁO: Chỉ chạy các test scripts trong môi trường test isolated!")


if __name__ == "__main__":
    main()