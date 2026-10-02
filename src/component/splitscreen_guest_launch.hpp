#pragma once

#include <atomic>

namespace splitscreen
{
	// Coordinates this component's two hold callbacks only. Engine accesses to
	// lobby memory do not participate in this guard.
	class guest_launch_coordinator
	{
	public:
		template <typename Callback>
		bool try_run(Callback&& callback)
		{
			if (busy_.test_and_set(std::memory_order_acquire))
			{
				return false; // Never wait on the renderer (or on a reentrant call).
			}

			struct release_on_exit
			{
				std::atomic_flag& busy;
				~release_on_exit()
				{
					busy.clear(std::memory_order_release);
				}
			} release{busy_};

			callback(); // Take the snapshot only after acquiring the guard.
			return true;
		}

	private:
		std::atomic_flag busy_ = ATOMIC_FLAG_INIT;
	};
}
