#!/bin/bash 
##############################################
# CyberAudit.sh
# Auteur: Beryith Keta
# Description: Script d'audit sécurité linux
# Version: 1.0
##############################################

#######################
# VARIABLES GLOBALES
#######################

VERSION="1.0"
REPORT_FILE="cyber_audit_rapport.txt"
VERBOSE=0
SECURITY_SCORE=100

#######################
#
#######################






#######################
# FONCTIONS UTILITAIRES
#######################
log() {
     echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"  >> "$LOG_FILE"
}
verbose() {
    if [ "$VERBOSE"  -eq 1 ]; then 
        echo -e "${BLUE} [VERBOSE]${RESET} $1"
    fi 
}

check_root() {
    if [ "EUID" -ne 0]; then 
        echo -e "${RED} Ce script doit etre exécuté en root.${RESET]"
        exit 1
    fi 
}

update_report() {
       echo "===== RAPPORT D'AUDIT CYBERSECURITE ===="> "$REPORT_FILE"
       echo "Date: $(date)" >> "$REPORT_FILE"
       echo "Machine: $(hostname)" >> "$REPORT_FILE"
       echo "= = = = = = = = = = = = = = = = = = = = =" >>
       echo "" >> "$REPORT_FILE"
}


##########################
# MODULE 1 : PORTS OUVERTS
##########################

check_point_ports() {
      echo " = = = PORTS OUVERTS = = =" | tee -a "$REPORT_FILE"
      ports=$(ss -tuln | grep LISTEN )
      
      if [ -z "$ports" ]; then 
          echo "Aucun port ouvert déctecté." | tee -a "REPORT_FILE"
      else 
          echo "$ports" | tee -a "$REPORT_FILE" 
      open_count=$(echo "$ports" | wc -l)
      update_score $((open_count * 2))
      fi
      echo "" >> "$REPORT_FILE"
      log "Analyse des ports terminée"
}

########################
# MODULE 2: UTILISATEURS
########################

check_users() { 
      echo "= = = UTILISATEURS AVEC SHELL ACTIF = = =" | tee -a "$REPORT_FILE"
      users=$(grep -E "/bin/bash| /bin/sh" /etc/passwd)
      echo "$users" | tee -a "$REPORT_FILE"

      user_count=$(echo "users" | wc -l)
      if [ "$user_count" -gt 5 ]; then 
          update_score 5
      fi

      echo ""  >> "REPORT_FILE"
      log "Analyse des utilisateurs terminée"
}

########################
# MODULE 3: FICHIRS SUID
########################

chek_suid() {
    echo " = = = FICHIERS SUID = = =" | tee -a "$REPORT_FILE"

    suid_files=$(find / -perm -4000 -type f 2>/dev/null))
    echo "$suid_files" | tee -a "$REPORT_FILE"

    suid_count=$(echo "$suid_files" | wc -l)
    if [ "$suid_count" -gt 20 ]; then 
       update_score 10
    fi

    echo "">> "REPORT_FILE"
    log "Analyse SUID terminée"
}

############################
# MODULE 4; SERVICES ACTIFS 
############################
 
check_services() {
     echo "= = = SERVICES ACTIFS = = ="| tee -a "REPORT_FILE"

     services=$(systemctl list-units --type=service --state=running) 
     echo "services" | tee -a "$REPORT_FILE"

     echo "" >> "REPORT_FILE"
     log "Analyse des services terminée"
}

#######################
# MODULE 5: MAJ SYSTEME
#######################

check_updates() {
     echo "= = = MISES A JOUR DISPONIBLE = = =" | tee -a "$REPORT_FILE"

     if command -v apt >/dev/null; then
         updates=$(apt list --upgradable 2>/dev/null | wc -l)
     echo "Paquets à mettre à jour: $updates" | tee -a "REPORT_FILE"

     if [ "$updates" -gt 10 ]; then 
         update_score 10 
     fi 
     
     echo "" >> "REPORT_FILE"
     log "Analyse des mises à jour terminée"
}

#######################
# MODULE 6: ANALYSE SSH
#######################
 check_ssh_failures() {
     echo "= = = ECHECS DE CONNEXION SSH = = =" | tee -a "$REPORT_FILE"

     if [ -f /var/log/auth.log]; then
          fails=$(grep "Failed password" /var/log/auth.log | tee -a "REPORT_FILE"
          echo "Tentatives échouées: $fails" | tee -a "REPORT_FILE"

          if [ "$fails" -gt 20]; then
                update_score 15
          fi
     else 
         echo "Fichiers auth.log introuvable." | tee -a "REPORT_FILE"
      fi 

      echo "" >> "REPORT_FILE"
      log "Analyse SSH terminée"
}

#############
# SCORE FINAL
#############

final_score() {
     echo "= = = SCORE FINAL = = =" | tee -a "REPORT_FILE"
     echo "Score de securité: $SECURITY_SCORE / 100" | tee -a "$REPORT_FILE"

     if [ "$SECURITY_SCORE" -ge 80 ];
        echo -e "${GREEN}Niveau de sécurité bon.${RESET}"
     elif [ "$SECURITY_SCORE" -ge 50] ; then 
        echo -e " ${YELLOW}SÉcurite moyenne. Améliorations recommandées.${RESET]"
     else 
        echo -e "${RED} Sécurité faible. Action requise.${RESET}"
     fi
  
     log "Score calculé"
}
################
#PARSE ARGUMENTS
################

while getopts "vh" opt; do
     case $opt in 
     v) VERBOSE=1 ;;
     h) usage ;;
     *) usage ;;
     esac 
done 

######################
# EXECUTION PRINCIPALE
######################

check_root
init_report 

echo -e "${BLUE} Démarrage de l'audit...${RESET}"

check_open_ports
check_users
check_suid
check_services
check_updates
check_ssh_failures
final_score  

echo -e "${GREEN}Audit terminé. Rapport généré: $REPORT_FILES${RESET}"
log "Audit complet terminé" 

exit 0
