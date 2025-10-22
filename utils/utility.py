from datetime import datetime
import time , string , random , asyncio
from flask import *
import uuid , os
import os
import resend
from PIL import Image  



# Needs To be Exported To Fit Environment Sec Rules  
resend.api_key = "re_C9UKrcbL_73NxSUTM8YuhEgQi5qQ14ngw"


app=Flask(__name__)



# Function To Yield System Formatted Time 
# Params : FORM : arguments to control specified time 

def Space_Time_Generator(Form) -> str:
    """A Function To Yield System Formatted Time In Layed Out Formats  """
    # Initiate The Time Object 
    TimeComponent = datetime.now()

    # Determine Printing Form --DateInt --Time  -DateString 
    if (Form == str('DateInt')) :
        # Returns Only The Date In Int Form 
        FormatedString =TimeComponent.strftime("%D")
    elif ( Form == str('DateStr')):
        # Returns The Day - Str , Date - Int and Year - Int e.g Sunday:05:2024
        FormatedString =TimeComponent.strftime(f"%A:%m:%Y")
    elif(Form == str('TimeStr')):
        # Returns int time in form of Hrs Min Sec
        FormatedString =TimeComponent.strftime(f"%H:%M:%S")
    elif(Form == str('Mutate')):
        # Returns the full string date object all in Int form such as : 05/19/24:04:40:38
        FormatedString =TimeComponent.strftime(f"%D:%H:%M:%S")


    return FormatedString 



# Unique Random Address Table 
# Return  Non - Reccurring Unique Addresses From The Random Module 
# Params : Int : A set of Random Numbers  To Be  Returned 
#        : Chars  :  Formulates The Alphabetical Table A-Z and Append The Int Range 0-9 For Random Number Generations 
# Returns A Formated String Object 

def Construct_String_Address(size, chars=string.ascii_uppercase + string.digits) -> str: 
    """ Creates A Random Int and String Character Sets For Unique Token Generations """
    return ''.join(random.choice(chars) for x in range(size))



# Unique Random Address Table 
# Return  Non - Reccurring Unique Addresses From The Random Module 
# Params : Int : A set of Random Numbers  To Be  Returned 
#        : Chars  :  Formulates  The Int Range 0-9 For Random Number Generations 
# Returns A Formated Int Object 
def Construct_Int_Address(size, chars=string.digits) -> str: 
    """ Creates A Unique Addresses For System Use . Current USe Cases Is To Provide A One Time 4 Set Token Number For OTP Verifications"""
    return ''.join(random.choice(chars) for x in range(size))





# A Function return profile avatars based on filepath   
# Fetches collectives on the said path and returns the length index after passing it random.randrange 


# A Color Visulaization Protocol 
# Developed to rteturn Color Profiles Based On randomly generated list indexes 
def ColorSort():
    " A Color mixer developed for profiling different elements by returning colorschemes in list based indexes  "
    Index = random.randrange(0,5)
    return Index




### Resend Emial Dispatsh Zone , 
### Section : Email * Superbase intergaration   


# Func : Initiates a dispatch email response  
# Dynamic & General Use Case with required parameters 
def Create_Email(Recipient , Subject , Body):
    print(Recipient , Subject , Body )
    if Body : 
        print(Recipient , Subject , Body )
        params: resend.Emails.SendParams = {
        "from": " info@prognosys <onboarding@resend.dev>",
        "to": [Recipient],
        "subject": Subject ,
        "html": Body ,
        }

        email = resend.Emails.send(params)
        print("SID ;" , Email )

    else: 
        return "Unable to create email : Reason : Empty Parameters supplied ! "
 


 ### HTML Based Emails Sections 
 ### Sending Graphical Emails Using Html 


# [DESC]Image Resizer Function Stack 
# [FUNCTION] Resolves Image Sizes based on Supplied Input  
# [ISSUES]Currently cannot read or processs rgba image files during conversion 
# [JOB]Essential for image editing and fixing   
# [PARAMS: ]

def Construct_Image_By_Size(input_folder, output_folder, size):  
    """Resize images in bulk.  

    Args:  
        input_folder (str): The folder containing images to resize.  
        output_folder (str): The folder to save resized images.  
        size (tuple): The desired size as (width, height).  
    """  
    # Create output directory if it doesn’t exist  
    if not os.path.exists(output_folder):  
        os.makedirs(output_folder)  

    for filename in os.listdir(input_folder):  
        if filename.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp')):  
            # Construct full file path  
            file_path = os.path.join(input_folder, filename)  
            
            try:  
                # Open an image file  
                with Image.open(file_path) as img:  
                    # Resize image  
                    img = img.resize(size)  

                    # Save resized image to output folder  
                    resized_file_path = os.path.join(output_folder, filename)  
                    img.save(resized_file_path)  
                    print(f'Resized and saved: {resized_file_path}')  
            except Exception as e:  
                print(f'Error processing {filename}: {e}')  

    if __name__ == "__main__":  
        input_folder = './in'  # Change as needed  
        output_folder = 'out'  # Change as needed  
        new_size = (400, 400)  # Desired size (width, height)  

    # Call Action 
    #Construct_Image_By_Size(input_folder, output_folder, new_size)  
