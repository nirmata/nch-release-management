#!/bin/bash
set -euo pipefail

results_dir="$1"
release="$2"
run_id="$3"

echo "========================================================"
echo "Generating SLA Report for release $release"
echo "========================================================"

# Load SLA configuration
sla_config_file="cve-management/slas.csv"
if [ ! -f "$sla_config_file" ]; then
  echo "⚠️ SLA configuration file not found: $sla_config_file"
  exit 0
fi

echo "📋 Loading SLA configuration from $sla_config_file"

# Create SLA report
sla_report_file="$results_dir/slas-report.json"

# Initialize SLA report structure
cat > "$sla_report_file" << EOJ
{
  "slaInfo": {
    "reportDate": "$(date -u '+%Y-%m-%d %H:%M:%S UTC')",
    "release": "$release",
    "workflowRun": "$run_id"
  },
  "blackList": [],
  "redList": [],
  "orangeList": [],
  "yellowList": []
}
EOJ

# Parse scan results and categorize CVEs
if [ ! -f "$results_dir/scan-grype.json" ]; then
  echo "⚠️ No scan results found, skipping SLA report generation"
  exit 0
fi

echo "🔍 Analyzing vulnerabilities for SLA compliance..."

# Create temporary files for each category
black_temp=$(mktemp)
red_temp=$(mktemp)
orange_temp=$(mktemp)
yellow_temp=$(mktemp)

current_date=$(date +%s)

# Process each image in the scan results
jq -c '.images[]' "$results_dir/scan-grype.json" | while read -r image_data; do
  image_name=$(echo "$image_data" | jq -r '.image')
  echo "  Analyzing image: $image_name"
  
  # Process each vulnerability in the image
  echo "$image_data" | jq -c '.scan.vulnerabilities[]?' | while read -r vuln; do
    vuln_id=$(echo "$vuln" | jq -r '.vulnerability')
    severity=$(echo "$vuln" | jq -r '.severity')
    fixed_in=$(echo "$vuln" | jq -r '.fixed_in')
    published_date=$(echo "$vuln" | jq -r '.published_date')
    
    # Only process CVEs with fixes available
    if [[ "$vuln_id" == CVE-* ]] && [ "$fixed_in" != "" ] && [ "$fixed_in" != "null" ]; then
      echo "    Processing: $vuln_id ($severity) - Fix: $fixed_in - Published: $published_date"
      
      # Get SLA days for this severity (convert to lowercase)
      severity_lower=$(echo "$severity" | tr '[:upper:]' '[:lower:]')
      sla_days=$(grep -i "^${severity_lower}," "$sla_config_file" | cut -d',' -f2 || echo "")
      
      if [ -n "$sla_days" ] && [ "$published_date" != "N/A" ]; then
        # Calculate days since publication (cross-platform compatible)
        if date -d "$published_date" +%s >/dev/null 2>&1; then
          # GNU date (Linux)
          published_epoch=$(date -d "$published_date" +%s)
        else
          # BSD date (macOS)
          published_epoch=$(date -j -f "%Y-%m-%d" "$published_date" +%s)
        fi
        
        days_elapsed=$(( (current_date - published_epoch) / 86400 ))
        days_remaining=$(( sla_days - days_elapsed ))
        
        echo "      SLA: $sla_days days, Elapsed: $days_elapsed days, Remaining: $days_remaining days"
        
        # Create vulnerability entry
        vuln_entry=$(jq -n \
          --arg vuln_id "$vuln_id" \
          --arg severity "$severity" \
          --arg published_date "$published_date" \
          --arg fixed_in "$fixed_in" \
          --arg image "$image_name" \
          --argjson days_elapsed "$days_elapsed" \
          --argjson days_remaining "$days_remaining" \
          --argjson sla_days "$sla_days" \
          '{
            vulnerability: $vuln_id,
            severity: $severity,
            publishedDate: $published_date,
            fixedIn: $fixed_in,
            daysElapsed: $days_elapsed,
            daysRemaining: $days_remaining,
            slaDays: $sla_days,
            images: [$image]
          }')
        
        # Categorize based on days remaining
        if [ "$days_remaining" -lt 0 ]; then
          echo "$vuln_entry" >> "$black_temp"
          echo "      → BLACK LIST (SLA exceeded by $((-days_remaining)) days)"
        elif [ "$days_remaining" -le 7 ]; then
          echo "$vuln_entry" >> "$red_temp"
          echo "      → RED LIST ($days_remaining days remaining)"
        elif [ "$days_remaining" -le 21 ]; then
          echo "$vuln_entry" >> "$orange_temp"
          echo "      → ORANGE LIST ($days_remaining days remaining)"
        else
          echo "$vuln_entry" >> "$yellow_temp"
          echo "      → YELLOW LIST ($days_remaining days remaining)"
        fi
      fi
    fi
  done
done

echo "✅ SLA analysis complete"
echo "📊 Generating consolidated SLA report..."

# Consolidate duplicate CVEs across images and rebuild the report
for category in black red orange yellow; do
  temp_file_var="${category}_temp"
  temp_file="${!temp_file_var}"
  
  if [ -f "$temp_file" ] && [ -s "$temp_file" ]; then
    # Group by vulnerability ID and merge images
    consolidated=$(jq -s '
      group_by(.vulnerability) | 
      map({
        vulnerability: .[0].vulnerability,
        severity: .[0].severity,
        publishedDate: .[0].publishedDate,
        fixedIn: .[0].fixedIn,
        daysElapsed: .[0].daysElapsed,
        daysRemaining: .[0].daysRemaining,
        slaDays: .[0].slaDays,
        images: (map(.images[]) | unique)
      })
    ' "$temp_file")
    
    # Update the SLA report with this category
    jq --argjson data "$consolidated" ".${category}List = \$data" "$sla_report_file" > "${sla_report_file}.tmp"
    mv "${sla_report_file}.tmp" "$sla_report_file"
  fi
  
  # Cleanup temp file
  rm -f "$temp_file"
done

echo "✅ SLA report generated: $sla_report_file"

# Display summary
black_count=$(jq '.blackList | length' "$sla_report_file")
red_count=$(jq '.redList | length' "$sla_report_file")
orange_count=$(jq '.orangeList | length' "$sla_report_file")
yellow_count=$(jq '.yellowList | length' "$sla_report_file")

echo ""
echo "📊 SLA Report Summary:"
echo "🔴 BLACK (SLA Exceeded): $black_count CVEs"
echo "🔴 RED (1-7 days left): $red_count CVEs"
echo "🟠 ORANGE (8-21 days left): $orange_count CVEs"
echo "🟡 YELLOW (>21 days left): $yellow_count CVEs"
