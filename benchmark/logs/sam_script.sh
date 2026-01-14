get_value() {
    local label="$1"
    local text="$2"
    echo "$text" | grep "$label" | awk -F': ' '{print $2}' | tr -d '[:space:]'
}

echo $(get_value "Average" "Average: 13310")
