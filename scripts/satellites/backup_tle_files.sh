#!/bin/bash

# TLE Files Backup Script
# This script creates backups of TLE files for satellite tracking

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TLE_UPDATE_DIR="${PROJECT_ROOT}/tle_data"
BACKUP_DIR="${PROJECT_ROOT}/tle_backup"
LOG_DIR="${PROJECT_ROOT}/logs"
MAX_BACKUP_FILES=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] ${message}${NC}"
}

# Function to create backup directory
create_backup_dir() {
    if [[ ! -d "${BACKUP_DIR}" ]]; then
        print_status "${BLUE}" "Creating backup directory: ${BACKUP_DIR}"
        mkdir -p "${BACKUP_DIR}"
    fi
}

# Function to backup TLE files
backup_tle_files() {
    print_status "${BLUE}" "Starting TLE files backup..."
    
    # Create backup directory
    create_backup_dir
    
    # Create timestamp for backup
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_subdir="${BACKUP_DIR}/tle_backup_${timestamp}"
    
    print_status "${BLUE}" "Creating backup: ${backup_subdir}"
    mkdir -p "${backup_subdir}"
    
    # Copy TLE files
    if [[ -d "${TLE_UPDATE_DIR}" ]]; then
        local tle_count=0
        for tle_file in "${TLE_UPDATE_DIR}"/*.tle; do
            if [[ -f "${tle_file}" ]]; then
                local filename=$(basename "${tle_file}")
                cp "${tle_file}" "${backup_subdir}/${filename}"
                print_status "${GREEN}" "Backed up: ${filename}"
                ((tle_count++))
            fi
        done
        
        if [[ ${tle_count} -eq 0 ]]; then
            print_status "${YELLOW}" "No TLE files found to backup"
        else
            print_status "${GREEN}" "Backed up ${tle_count} TLE files"
        fi
    else
        print_status "${YELLOW}" "TLE directory not found: ${TLE_UPDATE_DIR}"
    fi
    
    # Create backup info file
    cat > "${backup_subdir}/backup_info.txt" << EOF
TLE Files Backup
================
Backup Date: $(date)
Backup Directory: ${backup_subdir}
Source Directory: ${TLE_UPDATE_DIR}
TLE Files Count: ${tle_count}
Backup Created By: TLE Backup Script
EOF
    
    print_status "${GREEN}" "Backup completed: ${backup_subdir}"
    
    # Compress backup if requested
    if command -v tar &> /dev/null; then
        print_status "${BLUE}" "Compressing backup..."
        cd "${BACKUP_DIR}"
        tar -czf "tle_backup_${timestamp}.tar.gz" "tle_backup_${timestamp}"
        if [[ $? -eq 0 ]]; then
            rm -rf "tle_backup_${timestamp}"
            print_status "${GREEN}" "Compressed backup created: tle_backup_${timestamp}.tar.gz"
        else
            print_status "${RED}" "Failed to compress backup"
        fi
    fi
}

# Function to clean old backups
clean_old_backups() {
    print_status "${BLUE}" "Cleaning old backups (keeping ${MAX_BACKUP_FILES} most recent)..."
    
    if [[ -d "${BACKUP_DIR}" ]]; then
        # Count backup files
        local backup_count=$(find "${BACKUP_DIR}" -name "tle_backup_*.tar.gz" -o -name "tle_backup_*" -type d | wc -l)
        
        if [[ ${backup_count} -gt ${MAX_BACKUP_FILES} ]]; then
            local files_to_remove=$((backup_count - MAX_BACKUP_FILES))
            print_status "${BLUE}" "Removing ${files_to_remove} old backup(s)..."
            
            # Remove old backups (keep most recent)
            find "${BACKUP_DIR}" -name "tle_backup_*.tar.gz" -o -name "tle_backup_*" -type d | \
            sort | head -n ${files_to_remove} | \
            while read -r old_backup; do
                print_status "${YELLOW}" "Removing old backup: $(basename "${old_backup}")"
                rm -rf "${old_backup}"
            done
            
            print_status "${GREEN}" "Old backups cleaned"
        else
            print_status "${BLUE}" "No old backups to clean (${backup_count} backups, max: ${MAX_BACKUP_FILES})"
        fi
    else
        print_status "${YELLOW}" "Backup directory not found: ${BACKUP_DIR}"
    fi
}

# Function to show backup status
show_backup_status() {
    print_status "${BLUE}" "TLE Backup Status:"
    echo
    
    if [[ -d "${BACKUP_DIR}" ]]; then
        local backup_count=$(find "${BACKUP_DIR}" -name "tle_backup_*.tar.gz" -o -name "tle_backup_*" -type d | wc -l)
        print_status "${GREEN}" "Total backups: ${backup_count}"
        
        echo
        print_status "${BLUE}" "Recent backups:"
        find "${BACKUP_DIR}" -name "tle_backup_*.tar.gz" -o -name "tle_backup_*" -type d | \
        sort -r | head -n 5 | \
        while read -r backup; do
            local backup_name=$(basename "${backup}")
            local backup_size=""
            if [[ -f "${backup}" ]]; then
                backup_size=" ($(du -h "${backup}" | cut -f1))"
            elif [[ -d "${backup}" ]]; then
                backup_size=" ($(du -h "${backup}" | cut -f1))"
            fi
            echo "  ${backup_name}${backup_size}"
        done
        
        echo
        print_status "${BLUE}" "Backup directory size:"
        du -sh "${BACKUP_DIR}"
        
    else
        print_status "${RED}" "Backup directory not found: ${BACKUP_DIR}"
    fi
}

# Function to restore from backup
restore_from_backup() {
    local backup_name="$1"
    
    if [[ -z "${backup_name}" ]]; then
        print_status "${RED}" "Error: Backup name required"
        echo "Usage: $0 restore <backup_name>"
        echo "Available backups:"
        find "${BACKUP_DIR}" -name "tle_backup_*.tar.gz" -o -name "tle_backup_*" -type d | sort -r
        exit 1
    fi
    
    local backup_path="${BACKUP_DIR}/${backup_name}"
    
    if [[ ! -e "${backup_path}" ]]; then
        print_status "${RED}" "Error: Backup not found: ${backup_path}"
        exit 1
    fi
    
    print_status "${BLUE}" "Restoring from backup: ${backup_name}"
    
    # Create TLE directory if it doesn't exist
    mkdir -p "${TLE_UPDATE_DIR}"
    
    if [[ -f "${backup_path}" && "${backup_path}" == *.tar.gz ]]; then
        # Extract compressed backup
        print_status "${BLUE}" "Extracting compressed backup..."
        cd "${BACKUP_DIR}"
        tar -xzf "${backup_name}"
        local extracted_dir="${backup_name%.tar.gz}"
        if [[ -d "${extracted_dir}" ]]; then
            cp "${extracted_dir}"/*.tle "${TLE_UPDATE_DIR}/" 2>/dev/null
            rm -rf "${extracted_dir}"
            print_status "${GREEN}" "Restored from compressed backup"
        else
            print_status "${RED}" "Failed to extract backup"
            exit 1
        fi
    elif [[ -d "${backup_path}" ]]; then
        # Copy from directory backup
        print_status "${BLUE}" "Copying from directory backup..."
        cp "${backup_path}"/*.tle "${TLE_UPDATE_DIR}/" 2>/dev/null
        print_status "${GREEN}" "Restored from directory backup"
    else
        print_status "${RED}" "Error: Invalid backup format"
        exit 1
    fi
    
    # Count restored files
    local restored_count=$(find "${TLE_UPDATE_DIR}" -name "*.tle" | wc -l)
    print_status "${GREEN}" "Restored ${restored_count} TLE files to ${TLE_UPDATE_DIR}"
}

# Function to show help
show_help() {
    echo "TLE Files Backup Script"
    echo
    echo "Usage: $0 {backup|clean|status|restore <backup_name>|help}"
    echo
    echo "Commands:"
    echo "  backup              - Create a new backup of TLE files"
    echo "  clean               - Clean old backups (keep ${MAX_BACKUP_FILES} most recent)"
    echo "  status              - Show backup status"
    echo "  restore <name>      - Restore TLE files from backup"
    echo "  help                - Show this help message"
    echo
    echo "Configuration:"
    echo "  TLE directory: ${TLE_UPDATE_DIR}"
    echo "  Backup directory: ${BACKUP_DIR}"
    echo "  Max backups: ${MAX_BACKUP_FILES}"
    echo
    echo "Examples:"
    echo "  $0 backup"
    echo "  $0 clean"
    echo "  $0 status"
    echo "  $0 restore tle_backup_20250101_120000.tar.gz"
}

# Main script logic
case "${1:-help}" in
    backup)
        backup_tle_files
        ;;
    clean)
        clean_old_backups
        ;;
    status)
        show_backup_status
        ;;
    restore)
        restore_from_backup "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_status "${RED}" "Error: Unknown command '${1}'"
        echo
        show_help
        exit 1
        ;;
esac
