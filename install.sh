#!/bin/bash

BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' 

clear

cat << "EOF"
                                                            ««                              
                                                           ««««                              
                                                           «««                              
                                                           ««»                              
                                                          «««««                              
                                                        «««  «««««                          
                                                       «««     ««»««                        
                                                      «««        ««««««                      
                                                     ««            ««««««                    
                                                    ««               ««««««                  
                                                   ««                   «««««                
                                           ««««   «««                    ««««««              
                                     «»«««««««»«««««                      ««««««            
                         ««        ««««««««»«««««««                         «««««            
                      «««««        «««««««««««««««                           «««««          
                    ««««««««     ««««««««««»«««»««                            «««««          
                   ««««««»«««   ««««««««««««««««««                            ««««»          
                    ««««»««««»«««««»»«««««     ««                              «««««        
                     ««««««««««««««««««««      «»                              «««««        
                        ««««««««««««««««««««   «                              ««««««        
                       «»««»««««»«««««««  ««««««                              ««««««        
                     ««««««««««««««««««    «««««»««                           «««««  «      
                    ««««««««««««««««««««««««««««»«««««««««««««««««»«««««««««»««««««««««««««««
                ««  «««««««««««««     «««««««««««»«««««««««««««««««««»«     «««««««««««««««  
                ««««««««   ««««««««««««»««««««««««          ««««««««««««««««««««««««        
                ««         «««« « «»«««««««««  «««« ««                  ««««««««««««        
               ««      ««««««««««  ««««««»«««« « »«««««««««««««««««««««««««   «««««          
               ««««««««««««»«««««   ««««««« ««  ««««»««««                     ««««««        
                       ««««««««««    «««««   «« ««««««««««                    «««»«          
                       «««««««««««  «««»«««««««««««»«««««»««                  «««««          
                       ««««««««««««««««««««««««««««««««««««««««               «««»«          
                       «««««««««««««««««««««««««««««««««««««»««««««««         «««««          
                     ««««« ««««««»«««««««««««««««««««««««««««««««««««««»      «««««          
                    »««««««««««  ««««««««««««««««»»«»««««««««««»«««««««««    «««««          
                  ««««»««««     «««««««««««««»«««««««««««« «««««««««««»««   »««««            
                   «»«««»«««««««««««««««««»««« «««««««««»»«« ««««««««   « «««««»            
                    ««««««««««««««««««««««»«««««««««««««««««««« «««««««  «««««              
                       «««»»«««««««»»««««««««»««««««««««««««««««  ««««««««»«                
                       «««««««««««««»«»««««««««««««««««««»««««««« ««««««»«                  
                         ««««»«««««««««««««««««»««««««««  ««««««»« «««««                    
                          ««««»»«««««««««««««««««»«««««««  «««««««««««                      
                           ««»««»«««««««««««««««««««««««««  ««»«««««                        
                           «««««««««««««««««««««««««««««««« ««««««                          
                           «««««««««««««««««««««««««««««»«««  ««««                          
                           ««««««««««»««««««««««««««««»»««««  «»«                            
                          ««««««««««««««««««««««««««««««««««« ««««                          
                          «««««« ««««»««««««««««««««»«««»««««»««                            
                         «««««««««»««««««««»«««««««««««»«««««««««                            
                           »«««««««««««««««««««««««««»««««««««»«                            
                               ««««««»««««««««««««««««««««««                                
                                         ««««»«««««««                                                            

EOF

echo -e "${CYAN}             MINERVA NETWORK VULNERABILITY SCANNER v1.0${NC}"
echo -e "${BLUE}====================================================================${NC}\n"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Error: Este script necesita instalar paquetes del sistema.${NC}"
  echo -e "${RED}[!] Por favor, ejecútalo con permisos de administrador: sudo ./install.sh${NC}"
  exit
fi

USER_NAME=${SUDO_USER:-$USER}

echo -e "${YELLOW}[?] Configuración de la Base de Datos de Vulnerabilidades (NVD)${NC}"
echo -e "Para evitar bloqueos al consultar CVEs, es recomendable"
echo -e "utilizar una API Key gratuita de NIST (https://nvd.nist.gov/developers/request-an-api-key)"
echo -e ""
read -p "Introduce tu NVD API Key (o pulsa Enter para omitir): " NVD_KEY

if [ -n "$NVD_KEY" ]; then
    echo "NVD_API_KEY=$NVD_KEY" > .env
    chown $USER_NAME:$USER_NAME .env
    echo -e "${GREEN}[+] API Key guardada correctamente en el archivo .env${NC}\n"
else
    echo -e "${BLUE}[i] Omitido. Podrás añadirla manualmente más tarde en el archivo .env${NC}\n"
    touch .env
    chown $USER_NAME:$USER_NAME .env
fi

echo -e "${CYAN}[+] Instalando dependencias del sistema ${NC}"
apt-get update -qq
apt-get install -y nmap python3-venv python3-pip > /dev/null

echo -e "${CYAN}[+] Creando entorno virtual y estructura de directorios...${NC}"
sudo -u $USER_NAME mkdir -p data
sudo -u $USER_NAME python3 -m venv venv

echo -e "${CYAN}[+] Instalando dependencias de Python ${NC}"
sudo -u $USER_NAME ./venv/bin/pip install -r requirements.txt > /dev/null

echo -e "\n${BLUE}====================================================================${NC}"
echo -e "${GREEN}¡Minerva se ha instalado correctamente!${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "Para arrancar el servidor, ejecuta:"
echo -e "  ${YELLOW}1.${NC} source venv/bin/activate"
echo -e "  ${YELLOW}2.${NC} uvicorn app.main:app --host 0.0.0.0 --port 8000\n"