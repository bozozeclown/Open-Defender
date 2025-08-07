Get-ChildItem -Path . -Recurse -File | 
Where-Object { 
    $_.FullName -notlike "*\.git*" -and 
    $_.FullName -notlike "*\.venv*" -and
	$_.FullName -notlike "*\target*" 
} | 
Sort-Object FullName | 
ForEach-Object { 
    $relPath = $_.FullName.Substring((Get-Location).Path.Length + 1); 
    Add-Content -Path "project_concatenated.txt" -Value "=== $relPath ==="; 
    Add-Content -Path "project_concatenated.txt" -Value (Get-Content -Path $_.FullName -Raw); 
    Add-Content -Path "project_concatenated.txt" -Value ""; 
    Add-Content -Path "project_concatenated.txt" -Value "" 
}