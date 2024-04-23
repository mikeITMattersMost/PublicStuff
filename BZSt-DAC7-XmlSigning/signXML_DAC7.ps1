<#
    script to sign a DAC7 xml file for submitting it to the german "Bundeszentralamt fuer Steuern" via DIP mass data interface
    .net code for registering RSA-MGF1 as crypto algorithm was taken from https://stackoverflow.com/questions/22658526/rsassa-pss-without-parameters-using-sha-256-net-4-5-support
    free to use without any warranty 

    script will let you
    1. choose input xml via filepicker dialog
    2. choose signing cert from current user cert store (private key must be marked as exportable)
    3. choose target file name fpr signed xml
#>


Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$dotNetClassid =  ("RsaSsaPss" + (Get-Random))
$CryptoAlgHelperCode = @"
using System;
using System.Security.Cryptography;
namespace CryptoAlgHelper
{

public class $dotNetClassid
{
    public static void RegisterSha256RsaMgf1()
    {        
        CryptoConfig.AddAlgorithm(typeof(RsaPssSha256SignatureDescription), "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1");
    }    

    public class RsaPssSha256SignatureDescription : SignatureDescription
    {
        public RsaPssSha256SignatureDescription()
        {
            using (var rsa = RSACng.Create())
            {
                this.KeyAlgorithm = rsa.GetType().AssemblyQualifiedName; // Does not like a simple algorithm name, but wants a type name (AssembyQualifiedName in Core)
            }
            this.DigestAlgorithm = "SHA256";
            this.FormatterAlgorithm = typeof(RsaPssSignatureFormatter).FullName;
            this.DeformatterAlgorithm = typeof(RsaPssSignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            var signatureFormatter = new RsaPssSignatureFormatter();
            signatureFormatter.SetKey(key);
            signatureFormatter.SetHashAlgorithm(this.DigestAlgorithm);
            return signatureFormatter;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            var signatureDeformatter = new RsaPssSignatureDeformatter();
            signatureDeformatter.SetKey(key);
            signatureDeformatter.SetHashAlgorithm(this.DigestAlgorithm);
            return signatureDeformatter;
        }

        public class RsaPssSignatureFormatter : AsymmetricSignatureFormatter
        {
            private RSA Key { get; set; }
            private string HashAlgorithmName { get; set; }

            public override void SetKey(AsymmetricAlgorithm key)
            {
                this.Key = (RSA)key;
            }

            public override void SetHashAlgorithm(string strName)
            {
                // Verify the name                
                strName="SHA256";
                Oid.FromFriendlyName(strName, OidGroup.HashAlgorithm);                                                

                this.HashAlgorithmName = strName;
            }

            public override byte[] CreateSignature(byte[] rgbHash)
            {
                return this.Key.SignHash(rgbHash, new HashAlgorithmName(this.HashAlgorithmName), RSASignaturePadding.Pss);
            }
        }

        public class RsaPssSignatureDeformatter : AsymmetricSignatureDeformatter
        {
            private RSA Key { get; set; }
            private string HashAlgorithmName { get; set; }

            public override void SetKey(AsymmetricAlgorithm key)
            {
                this.Key = (RSA)key;
            }

            public override void SetHashAlgorithm(string strName)
            {
                // Verify the name
                strName="SHA256";
                Oid.FromFriendlyName(strName, OidGroup.HashAlgorithm);                
                this.HashAlgorithmName = strName;
            }

            public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
            {
                return this.Key.VerifyHash(rgbHash, rgbSignature, new HashAlgorithmName(this.HashAlgorithmName), RSASignaturePadding.Pss);
            }
        }
    }
}
}
"@
Add-Type -TypeDefinition $CryptoAlgHelperCode -Language CSharp	

function Sign-XML {
    Param (
        [xml]$xmlSignee,        
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$signCertificate,
        [string]$dotNetClassid
    )

    Invoke-Expression "[CryptoAlgHelper.$dotNetClassid]::RegisterSha256RsaMgf1()"

    [System.Security.Cryptography.xml.SignedXml]$signedXml = $null
    $signedXml = New-Object System.Security.Cryptography.Xml.SignedXml -ArgumentList $xmlSignee
    $signedXml.SigningKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($signCertificate)
       
    $signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";    

    $Reference = New-Object System.Security.Cryptography.Xml.Reference
    $Reference.Uri = ("#object")    
    $reference.DigestMethod = 'http://www.w3.org/2001/04/xmlenc#sha256'
    $signedXml.AddReference($Reference)    
    
    $keyInfo = New-Object System.Security.Cryptography.Xml.KeyInfo    
    $certData = New-Object System.Security.Cryptography.Xml.KeyInfoX509Data -ArgumentList $signCertificate
    [System.Security.Cryptography.X509Certificates.X500DistinguishedName]$dn = $signCertificate.SubjectName
    
    $certData.AddSubjectName($dn.Name)
    $keyInfo.AddClause($certData)    
        
    $signedXml.KeyInfo = $keyInfo
    $signedXml.ComputeSignature()
    
    [System.Xml.XmlElement]$xmlSignature = $signedXml.GetXml()
    return $xmlSignature
   
}

function Choose-SigningCert {

    $certPickerForm = New-Object System.Windows.Forms.Form
    $certPickerForm.Text = 'Signaturzertifikat wählen'  
    $certPickerForm.Size = New-Object System.Drawing.Size(440,280)
    $certPickerForm.StartPosition = 'CenterScreen'  

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(10,220)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'  
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $certPickerForm.AcceptButton = $okButton
    $certPickerForm.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(90,220)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Abbrechen'  
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $certPickerForm.CancelButton = $cancelButton
    $certPickerForm.Controls.Add($cancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = 'Zertifikat für die Signatur auswählen:'  
    $certPickerForm.Controls.Add($label)

    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(10,40)
    $listBox.Size = New-Object System.Drawing.Size(415,20)
    $listBox.Height = 180
    $listBox.HorizontalScrollbar = $true
    
    foreach ($cert in (Get-ChildItem -path cert:\CurrentUser\My)) {
            
        if ($cert.hasPrivateKey) {
         
            [void] $listBox.Items.Add($cert.Subject + ' (' + $cert.Thumbprint + ')')  
        }
    }
    
    $certPickerForm.Controls.Add($listBox)
    $certPickerForm.FormBorderStyle = 'FixedDialog'
    $certPickerForm.MaximizeBox = $false
    $certPickerForm.MinimizeBox = $false
    $topMost = New-Object 'System.Windows.Forms.Form' -Property @{TopMost=$true}

    if ($certPickerForm.ShowDialog($topMost) -eq [System.Windows.Forms.DialogResult]::OK) {

        return $listBox.SelectedItem
    }

    return ""
}

function Get-FileName($initialDirectory)
{  
 [System.Reflection.Assembly]::LoadWithPartialName(“System.windows.forms”) |
 Out-Null

 $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
 $OpenFileDialog.initialDirectory = $initialDirectory
 $OpenFileDialog.filter = “XML-Dateien (*.xml)| *.xml” 
 $OpenFileDialog.ShowDialog() | Out-Null
 return $OpenFileDialog.filename

}

function Get-SaveFileName([string] $initialDirectory){

    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "XML-Dateien (*.xml)| *.xml"
    $OpenFileDialog.ShowDialog() |  Out-Null

    return $OpenFileDialog.filename
}


$xmlToSignFilePath = Get-FileName
if ($xmlToSignFilePath -eq '') {

    Write-Error "Could not select input file"
    return $false    
}


[xml]$xmlToSign = Get-Content -Path $xmlToSignFilePath
$xmlToSign.PreserveWhitespace = $false

$dipElement = $xmlToSign.dip
if ($dipElement -eq $null) {

    Write-Error "Could not find dip-Element in input file"
    return $false 
}
    $xmlToSign.RemoveChild($dipElement)

$objectEnvelope = $xmlToSign.CreateElement('Object', 'http://www.w3.org/2000/09/xmldsig#')
    $objectEnvelopeId = $xmlToSign.CreateAttribute('Id')
    $objectEnvelopeId.Value = 'object'
    $objectEnvelope.Attributes.Append($objectEnvelopeId)

    $xmlToSign.AppendChild($objectEnvelope)
    $xmlToSign.object.AppendChild($dipElement)
    
[string]$signingCertThumprint = Choose-SigningCert
if ($signingCertThumprint -ne "" -and $signingCertThumprint -match '\((.+)\)') {

    $signingCertThumprint = $matches[1] 
} else {

    Write-Error "Could not select Certificate"
    return $false
}
[System.Security.Cryptography.X509Certificates.X509Certificate2]$signingCert = Get-ChildItem -path cert:\CurrentUser\My | where{$_.Thumbprint -eq $signingCertThumprint}
[System.Xml.XmlElement]$xmlSignature = Sign-XML -xmlSignee $xmlToSign -signCert $signingCert -dotNetClassid $dotNetClassid

$objectElement = $xmlToSign.object.Clone()
$xmlToSign.RemoveChild($xmlToSign.object)
$xmlToSign.AppendChild($xmlSignature)
$xmlToSign.Signature.AppendChild($objectElement)

$outFileName = Get-SaveFileName
$xmltw =  New-Object System.Xml.XmlTextWriter($outFileName, (New-Object System.Text.UTF8Encoding($false)))
$xmlToSign.WriteTo($xmltw)
$xmltw.Close()
