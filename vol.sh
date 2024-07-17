#!/bin/bash


#define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[1;33m'
DARK_GREEN='\033[0;32m'
RESET='\033[0m'



HOME=/home/kali/Desktop

#1.1 Check the current user; exit if not ‘root’.
if [ "$(whoami)" != "root" ]; then

    echo -e "${RED}Error: This Analyzer must be run as root.${RESET}"
    
        exit 1
        
        fi

REMOTE_REQUIREMENTS=( "foremost" "binwalk" "bulk_extractor" "exiftool")

#1.3 Create a function to install the forensics tools if missing.

function INSTALL_DEPENDENCIES()
{
    for package_name in "${REMOTE_REQUIREMENTS[@]}"; do
        dpkg -s "$package_name" >/dev/null 2>&1 || 
        (echo -e "[*] installing $package_name..." &&
        sudo apt-get install "$package_name" -y >/dev/null 2>&1)
        echo "[#] $package_name installed."
    done
}


#2.2 Find the memory profile and save it into a variable.
#2.3 Display the running processes.
#2.4 Display network connections.
#2.5 Attempt to extract registry information
function VOL()
{
#2.1 Check if the file can be analyzed in Volatility; if yes, run Volatility.
# Check if the file name contains ".mem"
if [[ "$file" == *".mem"* ]]; then
    echo " [**] File format recognized as a memory image. Proceeding with Volatility analysis..."
	
	
    mkdir "$HOME/Tool/vol_data" > /dev/null 2>&1
    PROFILE=$(./vol -f $file imageinfo 2>/dev/null | grep "Suggested Profile" | awk '{print $4}' | sed 's/,/ /g' | tr -d ' ')
	
    # Save the output to files
    ./vol -f "$file" --profile="$PROFILE" pstree > "$HOME/Tool/vol_data/vol_pstree" 2>&1
    sleep 1
    ./vol -f "$file" --profile="$PROFILE" connscan > "$HOME/Tool/vol_data/vol_conscan" 2>&1
    #2.5 Attempt to extract registry information.
    ./vol -f "$file" --profile="$PROFILE" hivelist > "$HOME/Tool/vol_data/vol_registry" 2>&1


    # Ask the user if they want to see the output in the terminal
    read -p "Do you want to see the output in the terminal? (y/n): " show_output

    #2.3 Display the running processes.
    echo "[+] Running Processes:"
    if [[ "$show_output" == "y" || "$show_output" == "Y" ]]; then
    echo "$(./vol -f "$file" --profile="$PROFILE" pstree)"


    else
        echo -e "${GREEN}Output saved to: ~/Desktop/Tool/vol_data/vol_pstree${RESET}"
    fi

    #2.4 Display network connections.
    echo "[+] Network Connections:"
    if [[ "$show_output" == "y" || "$show_output" == "Y" ]]; then
    echo "$(./vol -f "$file" --profile="$PROFILE" connscan)"

    else
        echo -e "${GREEN}Output saved to: ~/Desktop/Tool/vol_data/vol_conscan${RESET}"
    fi

else
    echo -e "${RED}[!] File format not recognized as a memory image. Cannot analyze with Volatility. Exiting...${RESET}"
    exit 1
fi

}



#1.4 Use different carvers to automatically extract data.

file=""  # Declare file outside of any function to make it global

function CARVERS()
{
	#1.2 Allow the user to specify the filename; check if the file exists.
echo -e "${ORANGE}\n[!] Please enter a full path to your memory file:${RESET}" && read -p "" file
	
	if [ -f "$file" ]; then
    echo "File '$file' exists."

	else
    echo -e "${RED}Error: File '$file' does not exist.${RESET}"
    exit 1
	fi 

	echo -e "${ORANGE}\n[!] Please choose the carver you would like to use:\n 1 - Exiftool\n 2 - Foremost\n 3 - Binwalk\n 4 - Bulk_Extractor\n 5 - All Carvers\n 6 - Volatility\n 99 - Exit${RESET}"
	read TOOLS

	case $TOOLS in
		
		1)
				mkdir "$HOME/Tool/exiftool" > /dev/null 2>&1
				exiftool "$file" >> "$HOME/Tool//exiftool.txt" 2>/dev/null
				echo -e "${GREEN}[+] DONE! data saved in ~/Desktop/Tool/exiftool${RESET}"

				ASK_FOR_STRINGS
				ASK_FOR_CARVERS
				MV_CHMOD
				STATISTIC_REPORT
		;;
		
		2)
				foremost $file -o $HOME/Tool/Foremost > /dev/null 2>&1
				echo -e "${GREEN}[+] DONE! data saved in ~/Desktop/Tool/foremost${RESET}"

				ASK_FOR_STRINGS
				ASK_FOR_CARVERS
				MV_CHMOD
				STATISTIC_REPORT
		;;
		
		3)
				binwalk --run-as=root -e $file -C $HOME/Tool/Binwalk > /dev/null 2>&1
				echo -e "${GREEN}[+] DONE! data saved in ~/Desktop/Tool/binwalk${RESET}"
				ASK_FOR_STRINGS
				ASK_FOR_CARVERS
				MV_CHMOD
				STATISTIC_REPORT
		;;
		
		4)
				
				bulk_extractor $file -o $HOME/Tool/Bulk_Extractor > /dev/null 2>&1
				#1.6 Attempt to extract network traffic; if found, display to the user the location and size.
				# Check for pcap files and print their sizes
				pcap_files=($(ls -l "$HOME/Tool/Bulk_Extractor" | grep pcap | awk '{print $9}'))
				if [ ${#pcap_files[@]} -gt 0 ]; then
					echo -e "${DARK_GREEN}[!] Found pcap files in Bulk_Extractor directory:${RESET}"
					for pcap_file in "${pcap_files[@]}"; do
						pcap_size=$(ls -l "$HOME/Tool/Bulk_Extractor/$pcap_file" | awk '{print $5}')
						echo "    $pcap_file - Size: $pcap_size bytes"
					done
				else
					echo "[!] No pcap files found in Bulk_Extractor directory."
				fi

				echo -e "${GREEN}[+] DONE! data saved in ~/Desktop/Tool/bulk_extractor${RESET}"
				ASK_FOR_STRINGS
				ASK_FOR_CARVERS
				MV_CHMOD
				STATISTIC_REPORT
		;;
		
		5)
				echo "[!] Using Exiftool..."
				mkdir "$HOME/Tool/exiftool" > /dev/null 2>&1
				exiftool "$file" >> "$HOME/Tool/exiftool/exiftool.txt" 2>/dev/null
				echo "[!] Using Foremost..."
				foremost $file -o $HOME/Tool/Foremost > /dev/null 2>&1
				echo "[!] Using Binwalk..."
				binwalk --run-as=root -e $file -C $HOME/Tool/Binwalk > /dev/null 2>&1
				echo "[!] Using Bulk_Extractor..."
				bulk_extractor $file -o $HOME/Tool/Bulk_Extractor > /dev/null 2>&1
				#1.6 Attempt to extract network traffic; if found, display to the user the location and size.
				# Check for pcap files and print their sizes
				pcap_files=($(ls -l "$HOME/Tool/Bulk_Extractor" | grep pcap | awk '{print $9}'))
				if [ ${#pcap_files[@]} -gt 0 ]; then
					echo -e "${DARK_GREEN}[!] Found pcap files in Bulk_Extractor directory:${RESET}"
					for pcap_file in "${pcap_files[@]}"; do
						pcap_size=$(ls -l "$HOME/Tool/Bulk_Extractor/$pcap_file" | awk '{print $5}')
						echo "    $pcap_file - Size: $pcap_size bytes"
					done
				else
					echo "[!] No pcap files found in Bulk_Extractor directory."
				fi

				echo -e "${GREEN}[+] DONE! data saved in ~/Desktop/Tool${RESET}"
				ASK_FOR_STRINGS
				ASK_FOR_CARVERS
				MV_CHMOD
				STATISTIC_REPORT
		;;
		
		6)		
				VOL
				echo -e "${GREEN}[+] DONE! data saved in ~/Desktop/Tool/vol_data${RESET}"

				ASK_FOR_STRINGS
				ASK_FOR_CARVERS
				MV_CHMOD
				STATISTIC_REPORT
		;;
		
		99)
			exit
		;;
		
		*)
			echo "Wrong option. try again."
			CARVERS
		;;
		
esac
}


#1.45 Ask the user if they want to use the CARVERS function again.
function ASK_FOR_CARVERS()
{
    echo -e "${ORANGE}\nDo you want to use the any CARVERS again? (yes/no): ${RESET}" && read -p "" use_carvers
    if [ "$use_carvers" = "yes" ]; then
        CARVERS
    else
        echo "Skipping CARVERS."
    fi
}

#1.78 Ask the user if they want to use the STRINGS function.
function ASK_FOR_STRINGS()
{
    echo -e "${ORANGE}\nDo you want to use the STRINGS to extract text from the file? (yes/no): ${RESET}" && read -p "" use_strings

    if [ "$use_strings" = "yes" ]; then
        STRINGS
    else
        echo "Skipping STRINGS."
    fi
}


#1.7 Check for human-readable (exe files, passwords, usernames, etc.).
function STRINGS ()
{

    mkdir "$HOME/Tool/Strings" > /dev/null 2>&1

    echo "[!] Using Strings to extract Human-readable text from the file"
    strings "$file" > "$HOME/Tool/Strings/strings" 2> /dev/null
    strings "$file" | grep -i "exe" > "$HOME/Tool/Strings/strings_exe" 2> /dev/null
    strings "$file" | grep -i "password" > "$HOME/Tool/Strings/strings_pass" 2> /dev/null
    strings "$file" | grep -i "username" > "$HOME/Tool/Strings/strings_users" 2> /dev/null
    strings "$file" | grep -iw "etc" > "$HOME/Tool/Strings/strings_etc" 2> /dev/null

    echo -e "${GREEN}[+] Human-readable text saved in: ~/Desktop/Tool/Strings/${RESET}"
}


#move the dir to kali Desktop and give it chmod 777
function MV_CHMOD ()
{	
 chmod 777 -R /home/kali/Desktop/Tool > /dev/null 2>&1
 chown kali:kali -R /home/kali/Desktop/Tool > /dev/null 2>&1
 
}




#making new directory on the Desktop.
#1.5 Data should be saved into a directory.
function START()
{
	# local analysis_start_time, for the stats of the statistics of the script
	local analysis_start_time
    analysis_start_time=$(date '+%Y-%m-%d %H:%M:%S')
    
	echo "[+] Creating a main directory on your Desktop named Tool...."
	mkdir $HOME/Tool > /dev/null 2>&1
	CARVERS
	
}


#3.1 Display general statistics (time of analysis, number of found files, etc.).
#3.2 Save all the results into a report (name, files extracted, etc.).
#3.3 Zip the extracted files and the report file.
function STATISTIC_REPORT() 
{
  # local analysis_start_time, in the start function.
  #  analysis_start_time=$(date '+%Y-%m-%d %H:%M:%S')

    # Obtain the analysis end time
    local analysis_end_time
    analysis_end_time=$(date '+%Y-%m-%d %H:%M:%S')

    # Calculate the duration of the analysis
    local analysis_duration
    analysis_duration=$(($(date -d "$analysis_end_time" '+%s') - $(date -d "$analysis_start_time" '+%s')))

    # List files in the directory and extract the number of files with data found
	local num_files
	num_files=$(ls -lR "$HOME/Tool/" | grep -e '^-' | awk '{if ($5 > 0) print}' | wc -l)
	
	# List files total size of non-empty files
	local total_size
	total_size=$(ls -lR "$HOME/Tool/" | grep -e '^-' | awk '{if ($5 > 0) print $5}' | awk '{sum += $1} END {print sum}')


	
    # Create a report file
    local report_file="$HOME/Tool/analysis_report.txt"
    echo "[Analysis Report]" > "$report_file"
    echo "Start Time: $analysis_start_time" >> "$report_file"
    echo "End Time: $analysis_end_time" >> "$report_file"
    echo "Analysis Duration: $analysis_duration seconds" >> "$report_file"
    echo "Number of Found Files: $num_files" >> "$report_file"
    echo "Total Size of Files: $total_size bytes" >> "$report_file"
    echo "" >> "$report_file"

    # Display statistics to the user
	echo -e "\n[Analysis Statistics]"
    echo "Start Time: $analysis_start_time"
    echo "End Time: $analysis_end_time"
    echo "Analysis Duration: $analysis_duration seconds"
	echo "Number of Files containing data: $num_files"
    echo "Total Size of Files: $total_size bytes"
    echo ""
    
    
}

#3.3 Zip the extracted files and the report file.
function ZIP_TOOL_DIRECTORY()
{
    # Zip the Tool directory
	echo "[*] ziping the Tool directory..."
    cd /home/kali/Desktop
    zip -r Tool.zip Tool >/dev/null 2>&1
    
    chmod 777 -R Tool.zip >/dev/null 2>&1
    chown kali:kali -R >/dev/null 2>&1
    echo "[+] Tool directory zipped successfully on your Desktop."
    
    #deleting the dir Tool
    rm -r /home/kali/Desktop/Tool 
    
    echo -e "[+] thx for using my script. bye bye :)"

}


INSTALL_DEPENDENCIES
START
ZIP_TOOL_DIRECTORY
