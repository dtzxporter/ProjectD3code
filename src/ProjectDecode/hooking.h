#pragma once

#include <cstdint>
#include <mutex>
#include <map>

// Convery hooks

namespace hooking
{
	// Basic interface for for various hooking types
	struct HookBase
	{
		uint8_t Savedcode[20];
		void *Savedlocation;
		void *Savedtarget;

		virtual bool Removehook() = 0;
		virtual bool Installhook(void *Location, void *Target) = 0;
		virtual bool Reinstall() { return Installhook(Savedlocation, Savedtarget); };
	};

	// Hook a target using a jmp instruction
	struct JmpHook : public HookBase
	{
		virtual bool Removehook() override;
		virtual bool Installhook(void *Location, void *Target) override;
	};

	// Hook a target using a call instruction
	struct Callhook : public HookBase
	{
		virtual bool Removehook() override;
		virtual bool Installhook(void *Location, void *Target) override;
	};
}