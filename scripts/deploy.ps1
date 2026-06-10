# deploy.ps1 — Deploy CloudFormation stack and Lambda code
# Usage: .\scripts\deploy.ps1 -Email "you@example.com" -Region "us-east-1"

param(
    [Parameter(Mandatory=$true)]
    [string]$Email,

    [string]$Region = "us-east-1",
    [string]$StackName = "security-drift-detective"
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " AWS Cloud Security Drift Detective" -ForegroundColor Cyan
Write-Host " Deploying to region: $Region" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Step 1: Deploy CloudFormation stack
Write-Host "`n[1/4] Deploying CloudFormation stack..." -ForegroundColor Yellow
aws cloudformation deploy `
    --template-file "$ProjectDir\infrastructure\template.yaml" `
    --stack-name $StackName `
    --parameter-overrides "AlertEmail=$Email" `
    --capabilities CAPABILITY_NAMED_IAM `
    --region $Region

if ($LASTEXITCODE -ne 0) {
    Write-Host "CloudFormation deployment failed!" -ForegroundColor Red
    exit 1
}

# Step 2: Package Lambda code
Write-Host "`n[2/4] Packaging Lambda function..." -ForegroundColor Yellow
$ZipPath = "$ProjectDir\lambda\drift_detector.zip"
$LambdaDir = "$ProjectDir\lambda\drift_detector"

if (Test-Path $ZipPath) { Remove-Item $ZipPath }
Compress-Archive -Path "$LambdaDir\*" -DestinationPath $ZipPath

# Step 3: Upload Lambda code
Write-Host "`n[3/4] Uploading Lambda code..." -ForegroundColor Yellow
aws lambda update-function-code `
    --function-name security-drift-detector `
    --zip-file "fileb://$ZipPath" `
    --region $Region

# Step 4: Enable CloudTrail EventBridge integration
Write-Host "`n[4/4] Enabling CloudTrail EventBridge integration..." -ForegroundColor Yellow
$Trails = aws cloudtrail describe-trails --region $Region --output json | ConvertFrom-Json

if ($Trails.trailList.Count -eq 0) {
    Write-Host "WARNING: No CloudTrail trail found. Create one first:" -ForegroundColor Red
    Write-Host "  aws cloudtrail create-trail --name security-trail --is-multi-region-trail --enable-log-file-validation" -ForegroundColor Gray
} else {
    $TrailName = $Trails.trailList[0].Name
    aws cloudtrail put-event-selectors `
        --trail-name $TrailName `
        --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true}]' `
        --region $Region 2>$null

    Write-Host "CloudTrail trail '$TrailName' configured." -ForegroundColor Green
}

# Print outputs
Write-Host "`n============================================" -ForegroundColor Green
Write-Host " DEPLOYMENT COMPLETE!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green

$Outputs = aws cloudformation describe-stacks `
    --stack-name $StackName `
    --region $Region `
    --query "Stacks[0].Outputs" `
    --output json | ConvertFrom-Json

foreach ($output in $Outputs) {
    Write-Host "  $($output.OutputKey): $($output.OutputValue)" -ForegroundColor White
}

Write-Host "`nNEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Check your email ($Email) and CONFIRM the SNS subscription" -ForegroundColor White
Write-Host "  2. Enable EventBridge on CloudTrail (AWS Console > CloudTrail > Trails > Edit > EventBridge: ON)" -ForegroundColor White
Write-Host "  3. Test: python scripts\local_test.py" -ForegroundColor White
Write-Host "  4. Trigger a test event in AWS to verify alerts" -ForegroundColor White
