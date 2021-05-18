#include "pch.h"
#include "TestModeEnabled.h"


BOOL IsTestModeEnabled()
{
	auto NtQuerySystemInformation = static_cast<pNtQuerySystemInformation>(API::GetAPI(API_IDENTIFIER::API_NtQuerySystemInformation));
	SYSTEM_CODEINTEGRITY_INFORMATION Integrity = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION), 0 };

	NTSTATUS status = NtQuerySystemInformation(103, &Integrity, sizeof(Integrity), NULL);

	return (status && (Integrity.CodeIntegrityOptions & 1));
}
