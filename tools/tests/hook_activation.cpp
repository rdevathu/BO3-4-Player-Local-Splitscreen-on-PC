// Link the actual standalone runtime with controlled MinHook outcomes. The
// companion script extracts the actual component helper and storage filter.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <MinHook.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <map>
#include "utils/hook.hpp"

namespace
{
	MH_STATUS initialize_status = MH_OK;
	MH_STATUS create_status = MH_OK;
	MH_STATUS enable_status = MH_OK;
	struct hook_entry
	{
		bool enabled = false;
		bool trampoline_in_flight = false;
	};
	std::map<void*, hook_entry> hooks;
	bool seated = true;
	int creates = 0, enables = 0, removes = 0, reads = 0;
	uint8_t image[64]{};
	constexpr uint8_t prologue[] = {0x40, 0x57, 0x48, 0x83, 0xEC, 0x20};

	void require(const bool condition, const char* message)
	{
		if (!condition)
		{
			std::fprintf(stderr, "FAIL: %s\n", message);
			std::exit(1);
		}
	}

	bool original_read(int, int, int) { ++reads; return true; }
	size_t base() { return reinterpret_cast<size_t>(image); }
	bool guest_has_local_client(int) { return seated; }
	template <typename... Args> void note(const char*, Args...) {}
	utils::hook::detour storage_read_hook;
	#include "hook_activation_component.inc"
	void stub() {}

	void expect_blocked(const int file_type)
	{
		const auto before = reads;
		require(!storage_read_stub(2, file_type, 0), "unsafe guest read must be refused");
		require(reads == before, "refused read must not invoke original");
	}
}

extern "C" MH_STATUS WINAPI MH_Initialize() { return initialize_status; }
extern "C" MH_STATUS WINAPI MH_CreateHook(LPVOID target, LPVOID, LPVOID* original)
{
	++creates;
	if (create_status != MH_OK) return create_status;
	if (hooks.contains(target)) return MH_ERROR_ALREADY_CREATED;
	*original = reinterpret_cast<void*>(&original_read);
	hooks[target] = {};
	return MH_OK;
}
extern "C" MH_STATUS WINAPI MH_EnableHook(LPVOID target)
{
	++enables;
	require(hooks.contains(target), "enable must target created hook");
	auto& entry = hooks.at(target);
	entry.enabled = enable_status == MH_OK || enable_status == MH_ERROR_ENABLED;
	// MinHook moves suspended instruction pointers before VirtualProtect. A
	// protection failure can resume threads in this still-disabled trampoline.
	entry.trampoline_in_flight = enable_status == MH_ERROR_MEMORY_PROTECT;
	return enable_status;
}
extern "C" MH_STATUS WINAPI MH_RemoveHook(LPVOID target)
{
	++removes;
	require(hooks.contains(target), "cleanup must target owned hook");
	require(!hooks.at(target).trampoline_in_flight || hooks.at(target).enabled,
	        "removing a disabled in-flight trampoline would free live execution");
	hooks.erase(target);
	return MH_OK;
}

int main(int argc, char**)
{
	for (size_t offset = 0; offset < sizeof(image); offset += 8)
	{
		std::memcpy(image + offset, prologue, sizeof(prologue));
	}
	utils::hook::detour hook;
	if (argc > 1)
	{
		initialize_status = MH_ERROR_MEMORY_ALLOC;
		require(!hook_if_stock(hook, 0, prologue, stub), "initialization failure must stay local");
		require(!creates && !enables && !removes, "initialization failure must not create hook");
		require(!hook.get_place() && !hook.get_original(), "failed initialization must leave no state");
		std::puts("PASS: initialization failure leaves guarded hook closed");
		return 0;
	}

	image[0] ^= 1;
	require(!hook_if_stock(hook, 0, prologue, stub), "prologue mismatch must fail");
	require(!creates, "prologue mismatch must not touch MinHook");
	image[0] ^= 1;

	create_status = MH_ERROR_UNSUPPORTED_FUNCTION;
	require(!hook_if_stock(hook, 0, prologue, stub), "create failure must stay local");
	require(!enables && !removes, "create failure must not enable or remove unowned hook");
	require(!hook.get_place() && !hook.get_original(), "create failure must clear state");
	create_status = MH_OK;

	size_t failed_offset = 0;
	for (const auto failure : {MH_ERROR_MEMORY_PROTECT, MH_ERROR_MEMORY_ALLOC})
	{
		enable_status = failure;
		const auto before = removes;
		require(!hook_if_stock(hook, failed_offset, prologue, stub), "enable failure must stay local");
		require(removes == before && hooks.contains(image + failed_offset), "failed trampoline must be retained");
		require(!hooks.at(image + failed_offset).enabled, "failed target must stay disabled");
		require(hooks.at(image + failed_offset).trampoline_in_flight == (failure == MH_ERROR_MEMORY_PROTECT),
		        "protection failure models redirected execution in retained trampoline");
		require(!hook.get_place() && !hook.get_original(), "enable failure must clear state");
		const auto before_enable = enables;
		require(!hook_if_stock(hook, failed_offset, prologue, stub), "same-target retry must fail already-created");
		require(enables == before_enable && removes == before, "retry must not activate or free retained entry");
		failed_offset += 8;
	}

	bool threw = false;
	enable_status = MH_ERROR_MEMORY_PROTECT;
	try { hook.create(image + 16, reinterpret_cast<void*>(&stub)); }
	catch (const std::exception&) { threw = true; }
	require(threw, "direct callers must receive activation exception");
	require(!hook.get_place() && !hook.get_original() && hooks.at(image + 16).trampoline_in_flight,
	        "direct failure must detach wrapper and retain in-flight trampoline");

	for (const auto success : {MH_OK, MH_ERROR_ENABLED})
	{
		enable_status = success;
		require(hook_if_stock(hook, 24, prologue, stub), "fresh target must activate normally");
		require(hooks.at(image + 24).enabled && hook.get_place() == image + 24 && hook.get_original(),
		        "success must retain usable trampoline");
		hook.clear();
	}

	// Install the read filter's original, then fail each completion hook. Use
	// the production flag assignment and verify the production filter refuses
	// the settings files without calling the original storage reader.
	storage_read_hook.create(image + 32, reinterpret_cast<void*>(&stub));
	enable_status = MH_ERROR_MEMORY_PROTECT;
	settings_result_neutered = hook_if_stock(hook, 40, prologue, stub);
	shoutcaster_result_neutered = hook_if_stock(hook, 48, prologue, stub);
	expect_blocked(0);
	expect_blocked(1);
	require(storage_read_stub(2, 12, 0), "guest stats must still pass after settings failure");
	require(storage_read_stub(0, 0, 0), "primary settings must still pass");
	// A later independent hook can activate; failure has not aborted setup.
	enable_status = MH_OK;
	settings_result_neutered = hook_if_stock(hook, 40, prologue, stub);
	expect_blocked(0); // A retained failed target cannot be retried.
	settings_result_neutered = hook_if_stock(hook, 56, prologue, stub);
	require(settings_result_neutered && storage_read_stub(2, 0, 0), "active settings completion opens its gate");
	expect_blocked(1);
	seated = false;
	expect_blocked(0);
	hook.clear();
	storage_read_hook.clear();
	require(hooks.size() == 5, "only failed entries remain retained for process lifetime");
	for (const auto& [target, entry] : hooks)
	{
		(void)target;
		require(!entry.enabled, "retained failure must not masquerade as an active hook");
	}
	std::puts("PASS: hook activation, retained in-flight trampolines, fresh targets and guest settings gates");
}
