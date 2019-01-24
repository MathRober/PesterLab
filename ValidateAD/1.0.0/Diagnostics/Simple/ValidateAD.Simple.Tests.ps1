Import-Module ActiveDirectory

$ADConfiguration = @{
    Forest = @{
        FQDN = 'dominio.local'
        ForestMode = 'Windows2016Forest'
        GlobalCatalogs = @(
            'DC01.dominio.local','DC02.dominio.local'
        )
        SchemaMaster = 'DC01.dominio.local'
        DomainNamingMaster = 'DC02.dominio.local'
    }
    Domain = @{
        NetBIOSName = 'dominio'
        DomainMode = 'Windows2016Domain'
        RIDMaster = 'DC01.dominio.local'
        PDCEmulator = 'DC01.dominio.local'
        InfrastructureMaster = 'DC01.dominio.local'
        DistinguishedName = 'DC=dominio,DC=local'
        DNSRoot = 'dominio.local'
        DomainControllers = @('DC01','DC02')
    }
    PasswordPolicy = @{
        PasswordHistoryCount = 24
        LockoutThreshold = 0
        LockoutDuration = '00:30:00'
        LockoutObservationWindow = '00:30:00'
        MaxPasswordAge = '42.00:00:00'
        MinPasswordAge = '1.00:00:00'
        MinPasswordLength = 7
        ComplexityEnabled = $true
    }
    Sites = @('Default-First-Site-Name')
    SiteLinks = @(
       [PSCustomObject]@{
            Name = 'DEFAULTIPSITELINK'
            Cost = 100
            ReplicationFrequencyInMinutes = 180
        }
    )
    SubNets = @(
        [PSCustomObject]@{
            Name = '10.0.1.0/24'
            Site = 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=dominio,DC=local'
        },
        [PSCustomObject]@{
            Name = '10.0.2.0/24'
            Site = 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=dominio,DC=local'
        }
    )

 Servicios = @{
	'DFS Namespace' = 'dfs'
	'DFS Replication' = 'dfsr'
	'Kerberos Key Distribution Center' = 'Kdc'
	'Windows Time' = 'w32time'
	'Active Directory Domain Service' = 'ntds'
	'Active Directory Web Services' = 'ADWS'
 }
 PuertosTCP = @{
        ldap = 389
        ldapssl = 636
        ldapgc = 3268
        ldapgcssl = 3269
        kerberos = 88
        kerberos2 = 464
        dns = 53
        smb = 445
        rpc = 135
        soap = 9389
        netbios = 139
        powershell = 5985
        powershelltls = 5986
    }    
}


Describe 'Comprobación de la configuración del Directorio Activo' {
    $Forest = Get-ADForest
    $DomainControllers = @(Get-ADDomainController -Filter *)
    $Domain = Get-ADDomain
    $DefaultDomainPasswordPolicy = Get-ADDefaultDomainPasswordPolicy
    $ReplicationSite = Get-ADReplicationSite -Filter *
    $ReplicationSiteLink = Get-ADReplicationSiteLink -Filter *
    $ReplicationSubnet = Get-ADReplicationSubnet -Filter *

    Context 'Configuración del bosque'{
        it "Forest FQDN $($ADConfiguration.Forest.FQDN)" {
            $Forest.RootDomain | Should Be $ADConfiguration.Forest.FQDN 
        }
        it "Modo funcional del bosque $($ADConfiguration.Forest.ForestMode)"{
            $Forest.ForestMode | Should Be $ADConfiguration.Forest.ForestMode 
        }
    }

    Context 'Comprobación de los catálogos globales'{

        $ADConfiguration.Forest.GlobalCatalogs | 
        ForEach-Object{
            it "Server $($_) is a GlobalCatalog"{
                $Forest.GlobalCatalogs.Contains($_) |   Should be $true
            }
        }
    }

    Context 'Comprobación de la configuración del dominio'{
        it "Total Domain Controllers $($ADConfiguration.Domain.DomainControllers.Count)" {
           $DomainControllers.Count | Should Be $ADConfiguration.Domain.DomainControllers.Count 
        }

        $ADConfiguration.Domain.DomainControllers | 
        ForEach-Object{
            it "DomainController $($_) exists"{
                $DomainControllers.Name.Contains($_) | Should be $true
            }
        }

        it "DNSRoot $($ADConfiguration.Domain.DNSRoot)"{
            $Domain.DNSRoot | Should Be $ADConfiguration.Domain.DNSRoot 
        }

        it "Nombre NetBIOS $($ADConfiguration.Domain.NetBIOSName)"{
            $Domain.NetBIOSName | Should Be $ADConfiguration.Domain.NetBIOSName 
        }

        it "Modo funcional del dominio $($ADConfiguration.Domain.DomainMode)"{
            $Domain.DomainMode |Should Be $ADConfiguration.Domain.DomainMode
        }

        it "Nombre Distinguido $($ADConfiguration.Domain.DistinguishedName)"{
            $Domain.DistinguishedName | Should Be $ADConfiguration.Domain.DistinguishedName
        }

        it "El servidor $($ADConfiguration.Domain.RIDMaster) es RIDMaster"{
            $Domain.RIDMaster | Should Be $ADConfiguration.Domain.RIDMaster
        }

        it "El servidor $($ADConfiguration.Domain.PDCEmulator) es PDCEmulator"{
            $Domain.PDCEmulator | Should Be $ADConfiguration.Domain.PDCEmulator
        }

        it "El servidor $($ADConfiguration.Domain.InfrastructureMaster) es InfrastructureMaster"{
            $Domain.InfrastructureMaster | Should Be $ADConfiguration.Domain.InfrastructureMaster
        }
    }

    Context 'Comprobación de la directiva de contraseñas predeterminada'{
        it 'Complejidad habilitada'{
            $DefaultDomainPasswordPolicy.ComplexityEnabled | Should Be  $ADConfiguration.PasswordPolicy.ComplexityEnabled
        }
        it 'Historial de contraseñas'{
            $DefaultDomainPasswordPolicy.PasswordHistoryCount | Should Be  $ADConfiguration.PasswordPolicy.PasswordHistoryCount
        }
        it "Bloqueo de cuentas: $($ADConfiguration.PasswordPolicy.LockoutThreshold)"{
            $DefaultDomainPasswordPolicy.LockoutThreshold | Should Be $ADConfiguration.PasswordPolicy.LockoutThreshold
        }
        it "Duración del bloqueo: $($ADConfiguration.PasswordPolicy.LockoutDuration)"{
            $DefaultDomainPasswordPolicy.LockoutDuration | Should Be  $ADConfiguration.PasswordPolicy.LockoutDuration
        }
        it "Lockout observation window equals $($ADConfiguration.PasswordPolicy.LockoutObservationWindow)"{
            $DefaultDomainPasswordPolicy.LockoutObservationWindow | Should Be  $ADConfiguration.PasswordPolicy.LockoutObservationWindow
        }
        it "Caducidad mínim de la contraseña: $($ADConfiguration.PasswordPolicy.MinPasswordAge)"{
            $DefaultDomainPasswordPolicy.MinPasswordAge | Should Be $ADConfiguration.PasswordPolicy.MinPasswordAge
        }
        it "Caducidad máxima de la contraseña: $($ADConfiguration.PasswordPolicy.MaxPasswordAge)"{
            $DefaultDomainPasswordPolicy.MaxPasswordAge | Should Be  $ADConfiguration.PasswordPolicy.MaxPasswordAge
        }
    }

    Context 'Sitios del Directorio Activo'{
        $ADConfiguration.Sites | 
        ForEach-Object{
            it "Site $($_)" {
                $ReplicationSite.Name.Contains($_) | 
                Should be $true
            } 
        }
    }
    Context 'Vínculos de sitios del Directorio Activo'{
        $lookupSiteLinks = $ReplicationSiteLink | Group-Object -AsHashTable -Property Name 
        $ADConfiguration.Sitelinks | 
        ForEach-Object{
            it "Vínculo de sitio: $($_.Name)" {
                $_.Name | 
                Should be $($lookupSiteLinks.$($_.Name).Name)
            } 
            it "Vínculo de sitio $($_.Name) Coste: $($_.Cost)" {
                $_.Cost | 
                Should be $lookupSiteLinks.$($_.Name).Cost
            }
            it "Vínculo de sitio: $($_.Name) Intervalo de repliación: $($_.ReplicationFrequencyInMinutes)" {
                $_.ReplicationFrequencyInMinutes | 
                Should be $lookupSiteLinks.$($_.Name).ReplicationFrequencyInMinutes
            }
        }
    }
    Context 'Subredes del Directorio Activo'{
        $lookupSubnets = $ReplicationSubnet | Group-Object -AsHashTable -Property Name 
        $ADConfiguration.Subnets | 
        ForEach-Object{
            it "Subred $($_.Name)" {
                $_.Name | 
                Should be $lookupSubnets.$($_.Name).Name
            }
            it "Sitio $($_.Site)" {
                $_.Site | 
                Should be $lookupSubnets.$($_.Name).Site
            }
        } 
    }
    
    Context ' Verificación de servicios'{
        foreach($dc in $ADConfiguration.Domain.DomainControllers){
		$ADConfiguration.Servicios.GetEnumerator() | 
        	ForEach-Object {
            		it "Comprobando el servicio  $($_.Key) en el DC $dc"  {
                		(Get-Service -Name $_.value -computer $dc).Status | Should Be 'Running'
            		}
        	}
	}
	
    }
    Context 'Verificación de puertos TCP'{
        foreach($dc in $ADConfiguration.Domain.DomainControllers){
		$ADConfiguration.PuertosTCP.GetEnumerator() | 
        	ForEach-Object {
            		it "Comprobando el puerto  $($_.Key) en el DC $dc"  {
                		(Test-NetConnection -computer $dc -port ([convert]::ToInt32($_.value, 10))).TcpTestSucceeded | Should Be 'True'
            		}
        	}
	}
    }

}


