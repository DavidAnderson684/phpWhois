<?php

/**
 * @license http://www.gnu.org/licenses/gpl-2.0.html GNU General Public License, version 2
 * @license
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * @copyright Copyright (c) 2023 Kevin Lucich
 */

namespace phpWhois;

use ArrayAccess;


class WhoIsData implements ArrayAccess
{
    /**
     * @var array Legacy information
     * @deprecated
     */
    public $regrinfo = [];

    /**
     * @var array Legacy information
     * @deprecated
     */
    public $regyinfo = [];

    /**
     * @var array con chi è stato registrato (Aruba, TopHost, ecc...)
     */
    protected $registrar_info = [];

    /**
     * @var array Domain info (domain_name, ecc...)
    */
    protected $domain_info = [];

    /**
     * @var array Registrant
     */
    protected $registrant_info = [];

    /**
     * @var array Admin info
     */
    protected $admin_info = [];

    /**
     * @var array Technical info
     */
    protected $technical_info = [];

    /**
     * @var string The raw response
     */
    protected $raw_data = '';


    public function getOwnerInfo(): array
    {
        return $this->owner_info;
    }

    public function setOwnerInfo( array $owner_info ): WhoIsData
    {
        $this->owner_info = $owner_info;
        return $this;
    }

    public function getRegistrarInfo(): array
    {
        return $this->registrar_info;
    }

    public function setRegistrarInfo( array $registrar_info ): WhoIsData
    {
        $this->registrar_info = $registrar_info;
        return $this;
    }

    public function getDomainInfo(): array
    {
        return $this->domain_info;
    }

    public function setDomainInfo( array $domain_info ): WhoIsData
    {
        $this->domain_info = $domain_info;
        return $this;
    }

    public function getRegistrantInfo(): array
    {
        return $this->registrant_info;
    }

    public function setRegistrantInfo( array $registrant_info ): WhoIsData
    {
        $this->registrant_info = $registrant_info;
        return $this;
    }

    public function getAdminInfo(): array
    {
        return $this->admin_info;
    }

    public function setAdminInfo( array $admin_info ): WhoIsData
    {
        $this->admin_info = $admin_info;
        return $this;
    }

    public function getTechnicalInfo(): array
    {
        return $this->technical_info;
    }

    public function setTechnicalInfo( array $technical_info ): WhoIsData
    {
        $this->technical_info = $technical_info;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getRawData()
    {
        return $this->raw_data;
    }

    /**
     * @param mixed $raw_data
     * @return WhoIsData
     */
    public function setRawData( $raw_data ): WhoIsData
    {
        $this->raw_data = $raw_data;
        return $this;
    }



    /////////////////////////////////////////
    // Access for backward compatibility

    public function offsetExists( $offset ): bool
    {
        $offset = ($offset === 'rawdata') ? 'raw_data' : $offset;
        return !empty($this->$offset);
    }

    public function offsetGet( $offset )
    {
        $offset = ($offset === 'rawdata') ? 'raw_data' : $offset;
        return $this->$offset;
    }

    public function offsetSet( $offset, $value ): void
    {
        $offset = ($offset === 'rawdata') ? 'raw_data' : $offset;
        $this->$offset = $value;
    }

    public function offsetUnset( $offset ): void
    {
        $offset = ($offset === 'rawdata') ? 'raw_data' : $offset;
        $this->$offset = null;
    }
}